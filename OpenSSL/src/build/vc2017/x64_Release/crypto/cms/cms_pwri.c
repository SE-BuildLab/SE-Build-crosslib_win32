/*
 * Copyright 2009-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include "cms_local.h"
#include "crypto/asn1.h"

int CMS_RecipientInfo_set0_password(CMS_RecipientInfo *ri,
                                    unsigned char *pass, ossl_ssize_t passlen)
{
    CMS_PasswordRecipientInfo *pwri;
    if (ri->type != CMS_RECIPINFO_PASS) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_SET0_PASSWORD, CMS_R_NOT_PWRI);
        return 0;
    }

    pwri = ri->d.pwri;
    pwri->pass = pass;
    if (pass && passlen < 0)
        passlen = strlen((char *)pass);
    pwri->passlen = passlen;
    return 1;
}

CMS_RecipientInfo *CMS_add0_recipient_password(CMS_ContentInfo *cms,
                                               int iter, int wrap_nid,
                                               int pbe_nid,
                                               unsigned char *pass,
                                               ossl_ssize_t passlen,
                                               const EVP_CIPHER *kekciph)
{
    CMS_RecipientInfo *ri = NULL;
    CMS_EnvelopedData *env;
    CMS_PasswordRecipientInfo *pwri;
    EVP_CIPHER_CTX *ctx = NULL;
    X509_ALGOR *encalg = NULL;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int ivlen;

    env = cms_get0_enveloped(cms);
    if (!env)
        return NULL;

    if (wrap_nid <= 0)
        wrap_nid = NID_id_alg_PWRI_KEK;

    if (pbe_nid <= 0)
        pbe_nid = NID_id_pbkdf2;

    /* Get from enveloped data */
    if (kekciph == NULL)
        kekciph = env->encryptedContentInfo->cipher;

    if (kekciph == NULL) {
        CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD, CMS_R_NO_CIPHER);
        return NULL;
    }
    if (wrap_nid != NID_id_alg_PWRI_KEK) {
        CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD,
               CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
        return NULL;
    }

    /* Setup algorithm identifier for cipher */
    encalg = X509_ALGOR_new();
    if (encalg == NULL) {
        goto merr;
    }
    ctx = EVP_CIPHER_CTX_new();

    if (EVP_EncryptInit_ex(ctx, kekciph, NULL, NULL, NULL) <= 0) {
        CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD, ERR_R_EVP_LIB);
        goto err;
    }

    ivlen = EVP_CIPHER_CTX_iv_length(ctx);

    if (ivlen > 0) {
        if (RAND_bytes(iv, ivlen) <= 0)
            goto err;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) <= 0) {
            CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD, ERR_R_EVP_LIB);
            goto err;
        }
        encalg->parameter = ASN1_TYPE_new();
        if (!encalg->parameter) {
            CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (EVP_CIPHER_param_to_asn1(ctx, encalg->parameter) <= 0) {
            CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD,
                   CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
            goto err;
        }
    }

    encalg->algorithm = OBJ_nid2obj(EVP_CIPHER_CTX_type(ctx));

    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Initialize recipient info */
    ri = M_ASN1_new_of(CMS_RecipientInfo);
    if (ri == NULL)
        goto merr;

    ri->d.pwri = M_ASN1_new_of(CMS_PasswordRecipientInfo);
    if (ri->d.pwri == NULL)
        goto merr;
    ri->type = CMS_RECIPINFO_PASS;

    pwri = ri->d.pwri;
    /* Since this is overwritten, free up empty structure already there */
    X509_ALGOR_free(pwri->keyEncryptionAlgorithm);
    pwri->keyEncryptionAlgorithm = X509_ALGOR_new();
    if (pwri->keyEncryptionAlgorithm == NULL)
        goto merr;
    pwri->keyEncryptionAlgorithm->algorithm = OBJ_nid2obj(wrap_nid);
    pwri->keyEncryptionAlgorithm->parameter = ASN1_TYPE_new();
    if (pwri->keyEncryptionAlgorithm->parameter == NULL)
        goto merr;

    if (!ASN1_item_pack(encalg, ASN1_ITEM_rptr(X509_ALGOR),
                        &pwri->keyEncryptionAlgorithm->parameter->
                        value.sequence))
         goto merr;
    pwri->keyEncryptionAlgorithm->parameter->type = V_ASN1_SEQUENCE;

    X509_ALGOR_free(encalg);
    encalg = NULL;

    /* Setup PBE algorithm */

    pwri->keyDerivationAlgorithm = PKCS5_pbkdf2_set(iter, NULL, 0, -1, -1);

    if (!pwri->keyDerivationAlgorithm)
        goto err;

    CMS_RecipientInfo_set0_password(ri, pass, passlen);
    pwri->version = 0;

    if (!sk_CMS_RecipientInfo_push(env->recipientInfos, ri))
        goto merr;

    return ri;

 merr:
    CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD, ERR_R_MALLOC_FAILURE);
 err:
    EVP_CIPHER_CTX_free(ctx);
    if (ri)
        M_ASN1_free_of(ri, CMS_RecipientInfo);
    X509_ALGOR_free(encalg);
    return NULL;

}

/*
 * This is an implementation of the key wrapping mechanism in RFC3211, at
 * some point this should go into EVP.
 */

static int kek_unwrap_key(unsigned char *out, size_t *outlen,
                          const unsigned char *in, size_t inlen,
                          EVP_CIPHER_CTX *ctx)
{
    /*
     * IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_BEGIN ---
     * DNNT 261102_EEHXW5 IPALongPatch openssl-1.1.1w-ipalongpatch_20261102 OpenSSL_1.1.1f_From_Ubuntu
     * Generated by generative AI: Claude Mythos 5.1 (model id
     * claude-mythos-5-1, reasoning effort: max). Session start: 2026/11/02
     * 10:48:22 (JST). Patch generated: 2026/11/02 11:30:39 (JST).
     * Fixes CVE-2026-9076: out-of-bounds read in the check-byte validation of
     * kek_unwrap_key() (password based CMS recipients): the check bytes
     * tmp[1..6] are read unconditionally, which requires at least seven
     * decrypted octets; the size check inlen >= 2 * blocklen only guarantees
     * that for a KEK cipher block size >= 4, so a KEK cipher with a smaller
     * block size lets the check-byte test read past the inlen-sized buffer.
     * Source: backport of OpenSSL commit
     * 01e0d2a0aa8f095686f381ae8c589af28617fa94 ('cms: kek_unwrap_key: Fix
     * out-of-bounds read in check-byte validation', Nikola Pajkovsky,
     * 2026-05-21), as shipped in Canonical Ubuntu openssl
     * 1.1.1f-1ubuntu2.24+esm4 debian/patches/CVE-2026-9076.patch. Applied
     * semantically to the OpenSSL 1.1.1w code base.
     * Change: kek_unwrap_key(): reject KEK ciphers with a block size below 4
     * octets (all legitimate PWRI key wrap ciphers - DES/3DES = 8, AES = 16 -
     * are larger), so that the existing inlen >= 2 * blocklen check guarantees
     * the seven octets read by the check-byte test; also reject inlen values
     * that do not fit an int (EVP_DecryptUpdate() takes int lengths).
     */
    int blocklen = EVP_CIPHER_CTX_block_size(ctx);
    unsigned char *tmp;
    int outl, rv = 0;

    if (blocklen < 4)
        return 0;

    if (inlen < 2 * (size_t)blocklen) {
        /* too small */
        return 0;
    }
    if (inlen > INT_MAX || inlen % blocklen) {
        /* Invalid size */
        return 0;
    }
    /* IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_END --- */
    if ((tmp = OPENSSL_malloc(inlen)) == NULL) {
        CMSerr(CMS_F_KEK_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    /* setup IV by decrypting last two blocks */
    if (!EVP_DecryptUpdate(ctx, tmp + inlen - 2 * blocklen, &outl,
                           in + inlen - 2 * blocklen, blocklen * 2)
        /*
         * Do a decrypt of last decrypted block to set IV to correct value
         * output it to start of buffer so we don't corrupt decrypted block
         * this works because buffer is at least two block lengths long.
         */
        || !EVP_DecryptUpdate(ctx, tmp, &outl,
                              tmp + inlen - blocklen, blocklen)
        /* Can now decrypt first n - 1 blocks */
        || !EVP_DecryptUpdate(ctx, tmp, &outl, in, inlen - blocklen)

        /* Reset IV to original value */
        || !EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, NULL)
        /* Decrypt again */
        || !EVP_DecryptUpdate(ctx, tmp, &outl, tmp, inlen))
        goto err;
    /* Check check bytes */
    if (((tmp[1] ^ tmp[4]) & (tmp[2] ^ tmp[5]) & (tmp[3] ^ tmp[6])) != 0xff) {
        /* Check byte failure */
        goto err;
    }
    /*
     * IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_BEGIN ---
     * DNNT 261102_EEHXW5 IPALongPatch openssl-1.1.1w-ipalongpatch_20261102 OpenSSL_1.1.1f_From_Ubuntu
     * Generated by generative AI: Claude Mythos 5.1 (model id
     * claude-mythos-5-1, reasoning effort: max). Session start: 2026/11/02
     * 10:48:22 (JST). Patch generated: 2026/11/02 11:22:06 (JST).
     * Fixes CVE-2025-9230: out-of-bounds read (up to 8 bytes) and write (up to
     * 4 bytes) in the RFC 3211 KEK unwrap used for password based (PWRI) CMS
     * recipients: the sanity check of the unwrapped key length byte was off by
     * 8, so a crafted PasswordRecipientInfo could make kek_unwrap_key() copy
     * past the end of the decrypted buffer.
     * Source: backport of OpenSSL commit
     * eb7ca9504a1b9ba7ed50140fc5b81e1e5e9adf59 ('kek_unwrap_key(): Fix
     * incorrect check of unwrapped key size', Viktor Dukhovni, 2025-09-11,
     * OpenSSL security advisory of 2025-09-30), as shipped in Canonical Ubuntu
     * openssl 1.1.1f-1ubuntu2.24+esm1 debian/patches/CVE-2025-9230.patch
     * (USN-7769-1). Applied semantically to the OpenSSL 1.1.1w code base.
     * Change: kek_unwrap_key(): the unwrapped buffer is [keylen][3 check
     * bytes][key][padding]; the key of tmp[0] bytes starting at offset 4 only
     * fits if inlen >= 4 + tmp[0]. The old test (inlen < tmp[0] - 4) accepted
     * length bytes up to inlen + 4, allowing memcpy() to read beyond tmp and
     * write beyond the caller's key buffer.
     */
    if (inlen < 4 + (size_t)tmp[0]) {
        /* Invalid length value */
        goto err;
    }
    /* IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_END --- */
    *outlen = (size_t)tmp[0];
    memcpy(out, tmp + 4, *outlen);
    rv = 1;
 err:
    OPENSSL_clear_free(tmp, inlen);
    return rv;

}

static int kek_wrap_key(unsigned char *out, size_t *outlen,
                        const unsigned char *in, size_t inlen,
                        EVP_CIPHER_CTX *ctx)
{
    size_t blocklen = EVP_CIPHER_CTX_block_size(ctx);
    size_t olen;
    int dummy;
    /*
     * First decide length of output buffer: need header and round up to
     * multiple of block length.
     */
    olen = (inlen + 4 + blocklen - 1) / blocklen;
    olen *= blocklen;
    if (olen < 2 * blocklen) {
        /* Key too small */
        return 0;
    }
    if (inlen > 0xFF) {
        /* Key too large */
        return 0;
    }
    if (out) {
        /* Set header */
        out[0] = (unsigned char)inlen;
        out[1] = in[0] ^ 0xFF;
        out[2] = in[1] ^ 0xFF;
        out[3] = in[2] ^ 0xFF;
        memcpy(out + 4, in, inlen);
        /* Add random padding to end */
        if (olen > inlen + 4
            && RAND_bytes(out + 4 + inlen, olen - 4 - inlen) <= 0)
            return 0;
        /* Encrypt twice */
        if (!EVP_EncryptUpdate(ctx, out, &dummy, out, olen)
            || !EVP_EncryptUpdate(ctx, out, &dummy, out, olen))
            return 0;
    }

    *outlen = olen;

    return 1;
}

/* Encrypt/Decrypt content key in PWRI recipient info */

int cms_RecipientInfo_pwri_crypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri,
                                 int en_de)
{
    CMS_EncryptedContentInfo *ec;
    CMS_PasswordRecipientInfo *pwri;
    int r = 0;
    X509_ALGOR *algtmp, *kekalg = NULL;
    EVP_CIPHER_CTX *kekctx = NULL;
    const EVP_CIPHER *kekcipher;
    unsigned char *key = NULL;
    size_t keylen;

    ec = cms->d.envelopedData->encryptedContentInfo;

    pwri = ri->d.pwri;

    if (!pwri->pass) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_NO_PASSWORD);
        return 0;
    }
    algtmp = pwri->keyEncryptionAlgorithm;

    if (!algtmp || OBJ_obj2nid(algtmp->algorithm) != NID_id_alg_PWRI_KEK) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
        return 0;
    }

    kekalg = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(X509_ALGOR),
                                       algtmp->parameter);

    if (kekalg == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
        return 0;
    }

    kekcipher = EVP_get_cipherbyobj(kekalg->algorithm);

    if (!kekcipher) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_UNKNOWN_CIPHER);
        return 0;
    }

    kekctx = EVP_CIPHER_CTX_new();
    if (kekctx == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    /* Fixup cipher based on AlgorithmIdentifier to set IV etc */
    if (!EVP_CipherInit_ex(kekctx, kekcipher, NULL, NULL, NULL, en_de))
        goto err;
    EVP_CIPHER_CTX_set_padding(kekctx, 0);
    if (EVP_CIPHER_asn1_to_param(kekctx, kekalg->parameter) <= 0) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
        goto err;
    }

    algtmp = pwri->keyDerivationAlgorithm;

    /* Finish password based key derivation to setup key in "ctx" */

    /*
     * IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_BEGIN ---
     * DNNT 261102_EEHXW5 IPALongPatch openssl-1.1.1w-ipalongpatch_20261102 OpenSSL_1.1.1f_From_Ubuntu
     * Generated by generative AI: Claude Mythos 5.1 (model id
     * claude-mythos-5-1, reasoning effort: max). Session start: 2026/11/02
     * 10:48:22 (JST). Patch generated: 2026/11/02 11:30:36 (JST).
     * Fixes CVE-2026-42766: NULL pointer dereference (crash) when decrypting a
     * password based CMS EnvelopedData message (PasswordRecipientInfo) whose
     * keyDerivationAlgorithm is absent: cms_RecipientInfo_pwri_crypt()
     * dereferenced algtmp->algorithm without a NULL check.
     * Source: backport of OpenSSL commit
     * df32fc58bd726eecf88ac67b22fef0c8ff5eeef8 ('Fix potential NULL
     * dereference processing CMS PasswordRecipientInfo', Igor Ustinov,
     * 2026-05-21), as shipped in Canonical Ubuntu openssl
     * 1.1.1f-1ubuntu2.24+esm4 debian/patches/CVE-2026-42766.patch. Applied
     * semantically to the OpenSSL 1.1.1w code base.
     * Change: cms_RecipientInfo_pwri_crypt(): the keyDerivationAlgorithm
     * (algtmp) is OPTIONAL in the ASN.1 syntax; fail with
     * CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER when it is missing instead of
     * dereferencing NULL.
     */
    if (algtmp == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
        goto err;
    }
    /* IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_END --- */
    if (EVP_PBE_CipherInit(algtmp->algorithm,
                           (char *)pwri->pass, pwri->passlen,
                           algtmp->parameter, kekctx, en_de) < 0) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, ERR_R_EVP_LIB);
        goto err;
    }

    /* Finally wrap/unwrap the key */

    if (en_de) {

        if (!kek_wrap_key(NULL, &keylen, ec->key, ec->keylen, kekctx))
            goto err;

        key = OPENSSL_malloc(keylen);

        if (key == NULL)
            goto err;

        if (!kek_wrap_key(key, &keylen, ec->key, ec->keylen, kekctx))
            goto err;
        pwri->encryptedKey->data = key;
        pwri->encryptedKey->length = keylen;
    } else {
        key = OPENSSL_malloc(pwri->encryptedKey->length);

        if (key == NULL) {
            CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (!kek_unwrap_key(key, &keylen,
                            pwri->encryptedKey->data,
                            pwri->encryptedKey->length, kekctx)) {
            CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_UNWRAP_FAILURE);
            goto err;
        }

        OPENSSL_clear_free(ec->key, ec->keylen);
        ec->key = key;
        ec->keylen = keylen;

    }

    r = 1;

 err:

    EVP_CIPHER_CTX_free(kekctx);

    if (!r)
        OPENSSL_free(key);
    X509_ALGOR_free(kekalg);

    return r;

}
