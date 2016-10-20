#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


#define GREEN "\e[01;32m"
#define YELLOW "\e[01;33m"
#define RESET_COLOR "\e[0m"

#define STATIC static inline

#define CA_CERT_DEFAULT "/ssl-certificates/CA/ca-cert.pem"
#define PORT_DEFAULT 4443


STATIC void init_openssl(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}

STATIC void cleanup_openssl(void)
{
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

STATIC SSL_CTX *create_context(const SSL_METHOD *method)
{
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

/* SSL debug */


STATIC void info_callback(const SSL* ssl, int where, int ret, const char* name) {

    if(ret == 0) {
        printf("info_callback: error occured \n");
        return;
    }

#define SSL_WHERE_INFO(ssl, w, flag, msg)                   \
{                                                           \
    if(w & flag) {                                          \
        printf(YELLOW);                                     \
        printf("+ %s: ", name);                             \
        printf("%20.20s", msg);                             \
        printf(" - %30.30s ", SSL_state_string_long(ssl));  \
        printf(" - %5.10s ", SSL_state_string(ssl));        \
        printf("\n");                                       \
        printf(RESET_COLOR);                                \
    }                                                       \
}

    SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");

#undef SSL_WHERE_INFO
}

STATIC int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    char    subject[256];
    char    issuer [256];
    char   *status;
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

    X509_NAME_oneline(X509_get_subject_name(current_cert), subject, sizeof(subject));
    X509_NAME_oneline(X509_get_issuer_name(current_cert), issuer, sizeof (issuer));

    status = preverify_ok ? "Accepting" : "Rejecting";

    printf("%s certificate for '%s' signed by '%s' \n", status, subject, issuer);

    return preverify_ok;
    //return 1;
}

#undef STATIC
#undef YELLOW
#undef GREEN
#undef RESET_COLOR
