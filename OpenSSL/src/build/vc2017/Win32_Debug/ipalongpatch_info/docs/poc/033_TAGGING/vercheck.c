#include <stdio.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
int main(void)
{
    printf("compile-time OPENSSL_VERSION_NUMBER = 0x%09lxL\n", (unsigned long)OPENSSL_VERSION_NUMBER);
    printf("compile-time OPENSSL_VERSION_TEXT   = \"%s\"\n", OPENSSL_VERSION_TEXT);
    printf("runtime OpenSSL_version_num()       = 0x%09lxL\n", (unsigned long)OpenSSL_version_num());
    printf("runtime OpenSSL_version(OPENSSL_VERSION) = \"%s\"\n", OpenSSL_version(OPENSSL_VERSION));
    printf("SHLIB_VERSION_NUMBER = \"%s\"\n", SHLIB_VERSION_NUMBER);
    return 0;
}
