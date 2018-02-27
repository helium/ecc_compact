/*
 * %CopyrightBegin%
 *
 * Copyright Helium Systems Inc 2018. All Rights Reserved.
 * Copyright Ericsson AB 2010-2017. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * %CopyrightEnd%
 */

/* These functions were extracted from Erlang's crypto.c OpenSSL NIF code */

#include "erl_nif.h"
#include <openssl/engine.h>
#include <openssl/obj_mac.h>

static int
term2point(ErlNifEnv * env, ERL_NIF_TERM term, EC_GROUP * group, EC_POINT ** pptr)
{
    int          ret = 0;
    ErlNifBinary bin;
    EC_POINT *   point;

    if (!enif_inspect_binary(env, term, &bin))
    {
        return 0;
    }

    if ((*pptr = point = EC_POINT_new(group)) == NULL)
    {
        return 0;
    }

    /* set the point conversion form */
    EC_GROUP_set_point_conversion_form(group, (point_conversion_form_t)(bin.data[0] & ~0x01));

    /* extract the ec point */
    if (!EC_POINT_oct2point(group, point, bin.data, bin.size, NULL))
    {
        EC_POINT_free(point);
        *pptr = NULL;
    }
    else
        ret = 1;

    return ret;
}

static int
get_bn_from_bin(ErlNifEnv * env, ERL_NIF_TERM term, BIGNUM ** bnp)
{
    ErlNifBinary bin;
    if (!enif_inspect_binary(env, term, &bin))
    {
        return 0;
    }
    *bnp = BN_bin2bn(bin.data, bin.size, NULL);
    return 1;
}

static ERL_NIF_TERM
bin_from_bn(ErlNifEnv * env, const BIGNUM * bn)
{
    int             bn_len;
    unsigned char * bin_ptr;
    ERL_NIF_TERM    term;

    /* Copy the bignum into an erlang binary. */
    bn_len  = BN_num_bytes(bn);
    bin_ptr = enif_make_new_binary(env, bn_len, &term);
    BN_bn2bin(bn, bin_ptr);

    return term;
}
