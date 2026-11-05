/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include "dh_local.h"

# define DH_NUMBER_ITERATIONS_FOR_PRIME 64

/*-
 * Check that p and g are suitable enough
 *
 * p is odd
 * 1 < g < p - 1
 */
int DH_check_params_ex(const DH *dh)
{
    int errflags = 0;

    if (!DH_check_params(dh, &errflags))
        return 0;

    if ((errflags & DH_CHECK_P_NOT_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_PARAMS_EX, DH_R_CHECK_P_NOT_PRIME);
    if ((errflags & DH_NOT_SUITABLE_GENERATOR) != 0)
        DHerr(DH_F_DH_CHECK_PARAMS_EX, DH_R_NOT_SUITABLE_GENERATOR);

    return errflags == 0;
}

int DH_check_params(const DH *dh, int *ret)
{
    int ok = 0;
    BIGNUM *tmp = NULL;
    BN_CTX *ctx = NULL;

    *ret = 0;
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

    if (!BN_is_odd(dh->p))
        *ret |= DH_CHECK_P_NOT_PRIME;
    if (BN_is_negative(dh->g) || BN_is_zero(dh->g) || BN_is_one(dh->g))
        *ret |= DH_NOT_SUITABLE_GENERATOR;
    if (BN_copy(tmp, dh->p) == NULL || !BN_sub_word(tmp, 1))
        goto err;
    if (BN_cmp(dh->g, tmp) >= 0)
        *ret |= DH_NOT_SUITABLE_GENERATOR;

    ok = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}

/*-
 * Check that p is a safe prime and
 * g is a suitable generator.
 */
int DH_check_ex(const DH *dh)
{
    int errflags = 0;

    if (!DH_check(dh, &errflags))
        return 0;

    if ((errflags & DH_NOT_SUITABLE_GENERATOR) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_NOT_SUITABLE_GENERATOR);
    if ((errflags & DH_CHECK_Q_NOT_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_Q_NOT_PRIME);
    if ((errflags & DH_CHECK_INVALID_Q_VALUE) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_INVALID_Q_VALUE);
    if ((errflags & DH_CHECK_INVALID_J_VALUE) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_INVALID_J_VALUE);
    if ((errflags & DH_UNABLE_TO_CHECK_GENERATOR) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_UNABLE_TO_CHECK_GENERATOR);
    if ((errflags & DH_CHECK_P_NOT_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_P_NOT_PRIME);
    if ((errflags & DH_CHECK_P_NOT_SAFE_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_P_NOT_SAFE_PRIME);

    return errflags == 0;
}

int DH_check(const DH *dh, int *ret)
{
    int ok = 0, r, q_good = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *t1 = NULL, *t2 = NULL;

    /* Don't do any checks at all with an excessively large modulus */
    if (BN_num_bits(dh->p) > OPENSSL_DH_CHECK_MAX_MODULUS_BITS) {
        DHerr(DH_F_DH_CHECK, DH_R_MODULUS_TOO_LARGE);
        *ret = DH_CHECK_P_NOT_PRIME;
        return 0;
    }

    if (!DH_check_params(dh, ret))
        return 0;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    if (t2 == NULL)
        goto err;

    if (dh->q != NULL) {
        if (BN_ucmp(dh->p, dh->q) > 0)
            q_good = 1;
        else
            *ret |= DH_CHECK_INVALID_Q_VALUE;
    }

    if (q_good) {
        if (BN_cmp(dh->g, BN_value_one()) <= 0)
            *ret |= DH_NOT_SUITABLE_GENERATOR;
        else if (BN_cmp(dh->g, dh->p) >= 0)
            *ret |= DH_NOT_SUITABLE_GENERATOR;
        else {
            /* Check g^q == 1 mod p */
            if (!BN_mod_exp(t1, dh->g, dh->q, dh->p, ctx))
                goto err;
            if (!BN_is_one(t1))
                *ret |= DH_NOT_SUITABLE_GENERATOR;
        }
        r = BN_is_prime_ex(dh->q, DH_NUMBER_ITERATIONS_FOR_PRIME, ctx, NULL);
        if (r < 0)
            goto err;
        if (!r)
            *ret |= DH_CHECK_Q_NOT_PRIME;
        /* Check p == 1 mod q  i.e. q divides p - 1 */
        if (!BN_div(t1, t2, dh->p, dh->q, ctx))
            goto err;
        if (!BN_is_one(t2))
            *ret |= DH_CHECK_INVALID_Q_VALUE;
        if (dh->j && BN_cmp(dh->j, t1))
            *ret |= DH_CHECK_INVALID_J_VALUE;
    }

    r = BN_is_prime_ex(dh->p, DH_NUMBER_ITERATIONS_FOR_PRIME, ctx, NULL);
    if (r < 0)
        goto err;
    if (!r)
        *ret |= DH_CHECK_P_NOT_PRIME;
    else if (!dh->q) {
        if (!BN_rshift1(t1, dh->p))
            goto err;
        r = BN_is_prime_ex(t1, DH_NUMBER_ITERATIONS_FOR_PRIME, ctx, NULL);
        if (r < 0)
            goto err;
        if (!r)
            *ret |= DH_CHECK_P_NOT_SAFE_PRIME;
    }
    ok = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}

int DH_check_pub_key_ex(const DH *dh, const BIGNUM *pub_key)
{
    int errflags = 0;

    if (!DH_check_pub_key(dh, pub_key, &errflags))
        return 0;

    if ((errflags & DH_CHECK_PUBKEY_TOO_SMALL) != 0)
        DHerr(DH_F_DH_CHECK_PUB_KEY_EX, DH_R_CHECK_PUBKEY_TOO_SMALL);
    if ((errflags & DH_CHECK_PUBKEY_TOO_LARGE) != 0)
        DHerr(DH_F_DH_CHECK_PUB_KEY_EX, DH_R_CHECK_PUBKEY_TOO_LARGE);
    if ((errflags & DH_CHECK_PUBKEY_INVALID) != 0)
        DHerr(DH_F_DH_CHECK_PUB_KEY_EX, DH_R_CHECK_PUBKEY_INVALID);

    return errflags == 0;
}

int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key, int *ret)
{
    int ok = 0;
    BIGNUM *tmp = NULL;
    BN_CTX *ctx = NULL;

    *ret = 0;
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);

    /*
     * IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_BEGIN ---
     * DNNT 261102_EEHXW5 IPALongPatch openssl-1.1.1w-ipalongpatch_20261102 OpenSSL_1.1.1f_From_Ubuntu
     * Generated by generative AI: Claude Mythos 5.1 (model id
     * claude-mythos-5-1, reasoning effort: max). Session start: 2026/11/02
     * 10:48:22 (JST). Patch generated: 2026/11/02 11:09:24 (JST).
     * Fixes CVE-2023-5678: excessive time spent in
     * DH_check_pub_key()/DH_generate_key()/DH_compute_key() with an
     * excessively large P or Q parameter (denial of service).
     * Source: backport of OpenSSL commit
     * ddeb4b6c6d527e54ce9a99cba785c0f7776e54b6 (master; 1.1.1-stable
     * cherry-pick db925ae2e65d0d925adef429afc37f75bd1c2017, 'Make
     * DH_check_pub_key() and DH_generate_key() safer yet', Richard Levitte,
     * 2023-10-20), as shipped in Canonical Ubuntu openssl
     * 1.1.1f-1ubuntu2.24+esm6 debian/patches/CVE-2023-5678.patch (USN-6622-1).
     * Applied semantically to the OpenSSL 1.1.1w code base.
     * Change: refuse to perform any (potentially very slow) modular
     * exponentiation when the modulus P exceeds
     * OPENSSL_DH_CHECK_MAX_MODULUS_BITS, and flag an invalid Q (Q larger than
     * P) before BN_mod_exp(tmp, pub_key, q, p) is attempted; this bounds the
     * work done on attacker supplied DH parameters. Behaviour mirrors
     * DH_check(): an oversized P is an error, an invalid Q is only reported
     * through *ret.
     */
    /* Don't do any checks at all with an excessively large modulus */
    if (BN_num_bits(dh->p) > OPENSSL_DH_CHECK_MAX_MODULUS_BITS) {
        DHerr(DH_F_DH_CHECK_PUB_KEY, DH_R_MODULUS_TOO_LARGE);
        *ret = DH_MODULUS_TOO_LARGE | DH_CHECK_PUBKEY_INVALID;
        goto err;
    }

    if (dh->q != NULL && BN_ucmp(dh->p, dh->q) < 0) {
        *ret |= DH_CHECK_INVALID_Q_VALUE | DH_CHECK_PUBKEY_INVALID;
        goto out;
    }
    /* IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_END --- */

    tmp = BN_CTX_get(ctx);
    if (tmp == NULL || !BN_set_word(tmp, 1))
        goto err;
    if (BN_cmp(pub_key, tmp) <= 0)
        *ret |= DH_CHECK_PUBKEY_TOO_SMALL;
    if (BN_copy(tmp, dh->p) == NULL || !BN_sub_word(tmp, 1))
        goto err;
    if (BN_cmp(pub_key, tmp) >= 0)
        *ret |= DH_CHECK_PUBKEY_TOO_LARGE;

    if (dh->q != NULL) {
        /* Check pub_key^q == 1 mod p */
        if (!BN_mod_exp(tmp, pub_key, dh->q, dh->p, ctx))
            goto err;
        if (!BN_is_one(tmp))
            *ret |= DH_CHECK_PUBKEY_INVALID;
    }

/*
 * IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_BEGIN ---
 * DNNT 261102_EEHXW5 IPALongPatch openssl-1.1.1w-ipalongpatch_20261102 OpenSSL_1.1.1f_From_Ubuntu
 * Generated by generative AI: Claude Mythos 5.1 (model id claude-mythos-5-1,
 * reasoning effort: max). Session start: 2026/11/02 10:48:22 (JST). Patch
 * generated: 2026/11/02 11:09:24 (JST).
 * Fixes CVE-2023-5678: excessive time spent in
 * DH_check_pub_key()/DH_generate_key()/DH_compute_key() with an excessively
 * large P or Q parameter (denial of service).
 * Source: backport of OpenSSL commit ddeb4b6c6d527e54ce9a99cba785c0f7776e54b6
 * (master; 1.1.1-stable cherry-pick db925ae2e65d0d925adef429afc37f75bd1c2017,
 * 'Make DH_check_pub_key() and DH_generate_key() safer yet', Richard Levitte,
 * 2023-10-20), as shipped in Canonical Ubuntu openssl 1.1.1f-1ubuntu2.24+esm6
 * debian/patches/CVE-2023-5678.patch (USN-6622-1). Applied semantically to the
 * OpenSSL 1.1.1w code base.
 * Change: 'out' label: successful return (ok = 1) after an early exit for an
 * invalid Q value detected above.
 */
 out:
/* IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_END --- */
    ok = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}
