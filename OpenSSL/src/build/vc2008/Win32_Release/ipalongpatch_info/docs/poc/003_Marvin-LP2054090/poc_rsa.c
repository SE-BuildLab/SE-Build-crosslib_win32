/*
 * PoC for item 003 (Marvin-LP2054090): RSA PKCS#1 v1.5 implicit rejection.
 *
 * Shows, for one RSA private key and a list of ciphertext files, what the
 * decryption API returns:
 *   - RSA_private_decrypt(..., RSA_PKCS1_PADDING)       (called twice -> determinism)
 *   - EVP_PKEY_decrypt() with default settings
 *   - EVP_PKEY_decrypt() with "rsa_pkcs1_implicit_rejection:0" (string ctrl, as
 *     used by `openssl pkeyutl -pkeyopt`) and with the numeric ctrl
 *     EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION
 *   - RSA_private_decrypt(..., RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING)
 *
 * Unpatched 1.1.1w: a padding failure is reported as an error (-1,
 * RSA_R_PKCS_DECODING_ERROR / RSA_R_PADDING_CHECK_FAILED) -> API oracle.
 * Patched: a deterministic synthetic message is returned instead (same for
 * the same ciphertext, different for different ciphertexts), unless implicit
 * rejection is explicitly disabled.
 *
 * "--timing N <good.bin> <bad.bin>" measures RSA_private_decrypt() with
 * RSA_PKCS1_PADDING for a valid and an invalid ciphertext (interleaved,
 * N iterations each) and prints min / quartiles / median / mean in ns.
 *
 * The same source is compiled against the unpatched and the patched build;
 * the macros below only provide the constants when the headers lack them.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>

#ifndef EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION
# define EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION (EVP_PKEY_ALG_CTRL + 14)
# define POC_HDR_HAS_IMPLICIT_REJECTION 0
#else
# define POC_HDR_HAS_IMPLICIT_REJECTION 1
#endif
#ifndef RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING
# define RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING 8
#endif

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long n;

    if (f == NULL) {
        perror(path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(n > 0 ? n : 1);
    if (fread(buf, 1, n, f) != (size_t)n) {
        perror("fread");
        exit(2);
    }
    fclose(f);
    *len = n;
    return buf;
}

static void print_result(const char *label, int ret, const unsigned char *out)
{
    if (ret < 0) {
        unsigned long e = ERR_peek_last_error();
        printf("  %-46s -> ERROR ret=%d : %s\n", label, ret,
               e ? ERR_error_string(e, NULL) : "(no error queued)");
        ERR_clear_error();
    } else {
        unsigned char md[SHA256_DIGEST_LENGTH];
        int i, show = ret < 24 ? ret : 24;

        SHA256(out, ret, md);
        printf("  %-46s -> OK len=%3d data=", label, ret);
        for (i = 0; i < show; i++)
            printf("%02x", out[i]);
        if (ret > show)
            printf("...");
        printf(" sha256(out)=");
        for (i = 0; i < 8; i++)
            printf("%02x", md[i]);
        printf("...\n");
    }
}

static int evp_decrypt(EVP_PKEY *pkey, const unsigned char *ct, size_t ctlen,
                       unsigned char *out, size_t outcap, int mode)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    size_t outlen = outcap;
    int rc, ret = -1;

    if (ctx == NULL || EVP_PKEY_decrypt_init(ctx) <= 0) {
        printf("  (EVP_PKEY_decrypt_init failed)\n");
        goto end;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        printf("  (set_rsa_padding failed)\n");
        goto end;
    }
    if (mode == 1) {
        rc = EVP_PKEY_CTX_ctrl_str(ctx, "rsa_pkcs1_implicit_rejection", "0");
        printf("  EVP_PKEY_CTX_ctrl_str(\"rsa_pkcs1_implicit_rejection\",\"0\") = %d%s\n",
               rc, rc <= 0 ? "  (ctrl NOT supported by this build)" : "");
        if (rc <= 0)
            ERR_clear_error();
    } else if (mode == 2) {
        rc = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_DECRYPT,
                               EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION, 0, NULL);
        printf("  EVP_PKEY_CTX_ctrl(EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION, 0) = %d%s\n",
               rc, rc <= 0 ? "  (ctrl NOT supported by this build)" : "");
        if (rc <= 0)
            ERR_clear_error();
    }
    rc = EVP_PKEY_decrypt(ctx, out, &outlen, ct, ctlen);
    ret = rc > 0 ? (int)outlen : -1;
 end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int cmp_u64(const void *a, const void *b)
{
    unsigned long long x = *(const unsigned long long *)a;
    unsigned long long y = *(const unsigned long long *)b;
    return x < y ? -1 : x > y;
}

static void stats(const char *label, unsigned long long *t, int n)
{
    double mean = 0;
    int i;

    qsort(t, n, sizeof(*t), cmp_u64);
    for (i = 0; i < n; i++)
        mean += (double)t[i];
    mean /= n;
    printf("  %-14s n=%d min=%llu q1=%llu median=%llu q3=%llu p90=%llu mean=%.0f (ns)\n",
           label, n, t[0], t[n / 4], t[n / 2], t[(3 * n) / 4], t[(9 * n) / 10],
           mean);
}

static unsigned long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int timing(RSA *rsa, const char *good, const char *bad, int n)
{
    size_t glen, blen;
    unsigned char *gct = read_file(good, &glen);
    unsigned char *bct = read_file(bad, &blen);
    unsigned char out[1024];
    unsigned long long *tg = malloc(n * sizeof(*tg));
    unsigned long long *tb = malloc(n * sizeof(*tb));
    int i, rg = 0, rb = 0;
    unsigned long long t0, t1;

    printf("Timing RSA_private_decrypt(RSA_PKCS1_PADDING), %d iterations each, interleaved\n", n);
    for (i = 0; i < n; i++) {
        t0 = now_ns();
        rg = RSA_private_decrypt((int)glen, gct, out, rsa, RSA_PKCS1_PADDING);
        t1 = now_ns();
        tg[i] = t1 - t0;
        ERR_clear_error();
        t0 = now_ns();
        rb = RSA_private_decrypt((int)blen, bct, out, rsa, RSA_PKCS1_PADDING);
        t1 = now_ns();
        tb[i] = t1 - t0;
        ERR_clear_error();
    }
    printf("  last return values: valid ciphertext -> %d, invalid ciphertext -> %d\n", rg, rb);
    stats("valid-padding", tg, n);
    stats("bad-padding", tb, n);
    qsort(tg, n, sizeof(*tg), cmp_u64);
    qsort(tb, n, sizeof(*tb), cmp_u64);
    printf("  median difference (bad - valid) = %lld ns  (%.2f %% of valid median)\n",
           (long long)tb[n / 2] - (long long)tg[n / 2],
           100.0 * ((double)tb[n / 2] - (double)tg[n / 2]) / (double)tg[n / 2]);
    free(gct);
    free(bct);
    free(tg);
    free(tb);
    return 0;
}

int main(int argc, char **argv)
{
    FILE *kf;
    EVP_PKEY *pkey;
    RSA *rsa;
    int i;

    if (argc < 3) {
        fprintf(stderr, "usage: %s key.pem ct.bin... | %s key.pem --timing N good.bin bad.bin\n",
                argv[0], argv[0]);
        return 2;
    }
    printf("Library: %s (headers: %s, implicit-rejection ctrl in headers: %s)\n",
           OpenSSL_version(OPENSSL_VERSION), OPENSSL_VERSION_TEXT,
           POC_HDR_HAS_IMPLICIT_REJECTION ? "yes" : "no");
    kf = fopen(argv[1], "r");
    if (kf == NULL) {
        perror(argv[1]);
        return 2;
    }
    pkey = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
    fclose(kf);
    if (pkey == NULL) {
        fprintf(stderr, "cannot read key\n");
        return 2;
    }
    rsa = EVP_PKEY_get0_RSA(pkey);

    if (strcmp(argv[2], "--timing") == 0) {
        if (argc < 6)
            return 2;
        timing(rsa, argv[4], argv[5], atoi(argv[3]));
        EVP_PKEY_free(pkey);
        return 0;
    }

    for (i = 2; i < argc; i++) {
        size_t ctlen;
        unsigned char *ct = read_file(argv[i], &ctlen);
        unsigned char out[1024];
        int ret;

        printf("Ciphertext file: %s (%zu bytes)\n", argv[i], ctlen);
        ret = RSA_private_decrypt((int)ctlen, ct, out, rsa, RSA_PKCS1_PADDING);
        print_result("RSA_private_decrypt(PKCS1_PADDING) #1", ret, out);
        ret = RSA_private_decrypt((int)ctlen, ct, out, rsa, RSA_PKCS1_PADDING);
        print_result("RSA_private_decrypt(PKCS1_PADDING) #2", ret, out);
        ret = evp_decrypt(pkey, ct, ctlen, out, sizeof(out), 0);
        print_result("EVP_PKEY_decrypt(default)", ret, out);
        ret = evp_decrypt(pkey, ct, ctlen, out, sizeof(out), 1);
        print_result("EVP_PKEY_decrypt(implicit_rejection:0 str)", ret, out);
        ret = evp_decrypt(pkey, ct, ctlen, out, sizeof(out), 2);
        print_result("EVP_PKEY_decrypt(IMPLICIT_REJECTION ctrl=0)", ret, out);
        ret = RSA_private_decrypt((int)ctlen, ct, out, rsa,
                                  RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING);
        print_result("RSA_private_decrypt(NO_IMPLICIT_REJECT=8)", ret, out);
        free(ct);
    }
    EVP_PKEY_free(pkey);
    return 0;
}
