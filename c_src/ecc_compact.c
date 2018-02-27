/*
 * Copyright 2018 Helium Systems Inc. All Rights Reserved.
 * Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include "erl_nif.h"

#include "ecc_compact_jivsov.h"
#include "ecc_compact_helpers.h"

typedef uint8_t felem_bytearray[32];
/* These are the parameters of P256, taken from FIPS 186-3, page 86. These
 * values are big-endian. */
/* clang-format off */
static const felem_bytearray nistp256_curve_params[5] = {
  {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,       /* p */
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,       /* a = -3 */
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc},      /* b */
  {0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
   0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
   0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
   0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b},
  {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,       /* x */
   0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
   0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
   0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96},
  {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,       /* y */
   0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
   0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
   0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5}
};
/* clang-format on */

static ERL_NIF_TERM atom_undefined;
static ERL_NIF_TERM atom_enomem;
static ERL_NIF_TERM atom_enotsup;

static    ERL_NIF_TERM
mk_atom(ErlNifEnv* env, const char* atom)
{
    ERL_NIF_TERM ret;

    if(!enif_make_existing_atom(env, atom, &ret, ERL_NIF_LATIN1))
    {
        return enif_make_atom(env, atom);
    }

    return ret;
}

static ERL_NIF_TERM recover(ErlNifEnv *env, int argc,
                            const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_badarg(env);
  }

  EC_KEY *key = NULL;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *tmp1, *tmp2, *x, *y, *p_y, *x_ = NULL;
  BIGNUM *curve_p, *curve_a, *curve_b;

  ERL_NIF_TERM ret;

  if (ctx == NULL) {
    return enif_raise_exception(env, atom_enomem);
  }

  tmp1 = BN_CTX_get(ctx);
  tmp2 = BN_CTX_get(ctx);
  x = BN_CTX_get(ctx);
  y = BN_CTX_get(ctx);
  p_y = BN_CTX_get(ctx);
  if (p_y == NULL) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }

  if (((curve_p = BN_CTX_get(ctx)) == NULL) ||
      ((curve_a = BN_CTX_get(ctx)) == NULL) ||
      ((curve_b = BN_CTX_get(ctx)) == NULL)) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }

  BN_bin2bn(nistp256_curve_params[0], sizeof(felem_bytearray), curve_p);
  BN_bin2bn(nistp256_curve_params[1], sizeof(felem_bytearray), curve_a);
  BN_bin2bn(nistp256_curve_params[2], sizeof(felem_bytearray), curve_b);

  key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (key == NULL) {
    ret = enif_raise_exception(env, atom_enotsup);
    goto err;
  }

  const BIGNUM *field = BN_get0_nist_prime_256();

  if (!get_bn_from_bin(env, argv[0], &x_)) {
    ret = enif_make_badarg(env);
    goto err;
  }

  /*-
   * Recover y.  We have a Weierstrass equation
   *     y^2 = x^3 + a*x + b,
   * so  y  is one of the square roots of  x^3 + a*x + b.
   */

  /* tmp1 := x^3 */
  if (!BN_nnmod(x, x_, field, ctx)) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }
  if (!BN_mod_sqr(tmp2, x_, field, ctx)) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }
  if (!BN_mod_mul(tmp1, tmp2, x_, field, ctx)) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }

  /* tmp1 := tmp1 + a*x */
  /* we can take the shortcut because a is -3 */
  if (!BN_mod_lshift1_quick(tmp2, x, field)) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }
  if (!BN_mod_add_quick(tmp2, tmp2, x, field)) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }
  if (!BN_mod_sub_quick(tmp1, tmp1, tmp2, field)) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }

  /* tmp1 := tmp1 + b */
  if (!BN_mod_add_quick(tmp1, tmp1, curve_b, field)) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }

  if (!BN_mod_sqrt(y, tmp1, field, ctx)) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }

  /* ok, we recovered y */

  /* compute p - y */
  if (!BN_mod_sub_quick(p_y, curve_p, y, field)) {
    ret = enif_raise_exception(env, atom_enomem);
    goto err;
  }

  /* find min(y, p-y) */
  if (BN_cmp(y, p_y) < 0) {
    ret = bin_from_bn(env, y);
  } else {
    ret = bin_from_bn(env, p_y);
  }

err:
    if (ctx) {
        BN_CTX_free(ctx);
    }
    if (key) {
        EC_KEY_free(key);
    }
    if (x_) {
        BN_clear_free(x_);
    }

    return ret;
}

    static ERL_NIF_TERM
is_compact(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EC_KEY *key = NULL;
    EC_POINT *pub_key = NULL;
    BN_CTX *ctx = NULL;
    EC_GROUP *group = NULL;

    ERL_NIF_TERM ret = mk_atom(env, "false");

    if(argc != 1)
    {
        return enif_make_badarg(env);
    }

    if (!enif_is_binary(env, argv[0]))
    {
        return enif_make_badarg(env);
    }

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
    {
        ret = enif_raise_exception(env, atom_enotsup);
        goto out_err;
    }

    group = EC_GROUP_dup(EC_KEY_get0_group(key));

    if (term2point(env, argv[0], group, &pub_key)) {
        if (!EC_KEY_set_public_key(key, pub_key)) {
            ret = enif_raise_exception(env, atom_enotsup);
            goto out_err;
        }
    } else {
        ret = enif_raise_exception(env, atom_enotsup);
        goto out_err;
    }

    if ((ctx = BN_CTX_new()) == NULL)
    {
        ret = enif_raise_exception(env, atom_enomem);
        goto out_err;
    }

    int is_c = is_compliant(pub_key, group, ctx);

    if (is_c == 0) {
        ret = mk_atom(env, "true");
    } else if (is_c == -1) {
        ret = enif_raise_exception(env, atom_enomem);
    }

out_err:
    if (key) {
        EC_KEY_free(key);
    }

    if (ctx) {
        BN_CTX_free(ctx);
    }

    if (pub_key) {
        EC_POINT_free(pub_key);
    }

    if (group) {
        EC_GROUP_free(group);
    }
    return ret;
}

static ErlNifFunc nif_funcs[] = {
    {"is_compact_nif", 1, is_compact, 0},
    {"recover_nif", 1, recover, 0}
};

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
  (void)priv_data;
  (void)load_info;
  atom_undefined = enif_make_atom(env, "undefined");
  atom_enomem = enif_make_atom(env, "enomem");
  atom_enomem = enif_make_atom(env, "enotsup");
  return 0;
}

ERL_NIF_INIT(ecc_compact, nif_funcs, load, NULL, NULL, NULL);
