/* Copyright (c) 2014 IETF Trust and the persons identified as authors of the
 * code. All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * Neither the name of Internet Society, IETF or IETF Trust, nor the names of
 * specific contributors, may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


/* The following code was taken from
 * http://openssl.6102.n7.nabble.com/openssl-org-3069-An-enhancement-to-EC-key-generation-to-enable-compact-point-representation-td45440.html
 * which was proposed as a patch by Andrey Jivsov <crypto@brainhub.org> as part
 * of https://tools.ietf.org/html/draft-jivsov-ecc-compact-05
 * As per the IETF draft this code is under the Simplified BSD License from
 * section 4.e at http://trustee.ietf.org/license-info/IETF-TLP-4.htm
 */
int is_compliant(EC_POINT *pub_key, const EC_GROUP *group, BN_CTX *ctx)
{
    /* We want the Q=(x,y) be a "compliant key" in terms of the
     * http://tools.ietf.org/html/draft-jivsov-ecc-compact,
     * which simply means that we choose either Q=(x,y) or -Q=(x,p-y) such that
     * we end up with the min(y,p-y) as the y coordinate.
     * Such a public key allows the most efficient compression: y can simply be
     * dropped because without any loss of security.
     * Given the x, we know that the y is a minimum of the two possibilities.
     */
    const EC_METHOD *meth = EC_GROUP_method_of(group);
    const int is_prime = (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field);

    if( is_prime )  {
        BIGNUM *ec_p, *ec_a, *ec_b, *ec_p_y, *ec_x, *ec_y;

        ec_p = BN_CTX_get(ctx);
        ec_a = BN_CTX_get(ctx);
        ec_b = BN_CTX_get(ctx);
        ec_p_y = BN_CTX_get(ctx);
        ec_x = BN_CTX_get(ctx);
        ec_y = BN_CTX_get(ctx);

        if (ec_p == NULL || ec_a == NULL || ec_b == NULL || ec_p_y == NULL)
        {
            return -1;
        }
        if (!EC_GROUP_get_curve_GFp(group, ec_p, ec_a, ec_b, NULL))  {
            return -1;
        }
        if (!EC_POINT_get_affine_coordinates_GFp(group, pub_key, ec_x, ec_y, ctx))  {
            return -1;
        }
        BN_sub(ec_p_y, ec_p, ec_y);

        if( BN_cmp(ec_p_y, ec_y) < 0  )  {
            return 1; /* false */
        } else {
            return 0; /* true */
        }
    }
    return 1;
}

