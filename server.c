#include "common.h"

#define SERVER_KEY_DEFAULT "/ssl-certificates/server/server-key.pem"
#define SERVER_CERT_DEFAULT "/ssl-certificates/server/server-cert.pem"

static int _s_port = -1;
static char *_s_server_key = NULL;
static char *_s_server_cert = NULL;
static char *_s_trusted_cert = NULL;

static void print_usage(void)
{
    printf("Usage: ./secure-server [-p port] [-k /path/to/private/server/key.pem]"
           "[-s /path/to/server-cert.pem] [-c /path/to/ca-cert.pem]\n");
    exit(EXIT_SUCCESS);
}

static void parse_args(int argc, char *argv[])
{
    char c;

    while ((c = getopt (argc, argv, "hp:k:c:s:")) != -1) {
        switch (c) {
        case 'p':
            _s_port = atoi(optarg);
            break;
        case 'k':
            _s_server_key = optarg;
            break;
        case 's':
            _s_server_cert = optarg;
            break;
        case 'c':
            _s_trusted_cert = optarg;
            break;
        case 'h':
            print_usage();
            break;
        }
    }
    if (_s_port <= 0 || _s_port > 65535) {
        _s_port = PORT_DEFAULT;
        printf("Port not provided. Use '%d' as default. \n", _s_port);
    }
    if (!_s_server_key) {
        _s_server_key = SERVER_KEY_DEFAULT;
        printf("Private key was not provided. Use default path '%s'\n",
               _s_server_key);
    }
    if (!_s_server_cert) {
        _s_server_cert = SERVER_CERT_DEFAULT;
        printf("Server certificate was not provided. Use default path '%s'\n",
               _s_server_cert);
    }
    if (!_s_trusted_cert) {
        _s_trusted_cert = CA_CERT_DEFAULT;
        printf("CA certificate was not provided. Use default path '%s'\n",
               _s_trusted_cert);
    }
}

static int create_server_socket(int port)
{
    int fd;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed \n");
    }

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(fd, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return fd;
}

static void server_info_callback(const SSL* ssl, int where, int ret)
{
    info_callback(ssl, where, ret, "server");
}

static void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, _s_server_cert, SSL_FILETYPE_PEM) < 0) {
        fprintf(stderr, "Error loading server certificate from file");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
//    if (SSL_CTX_use_certificate_chain_file(ctx, _s_server_cert) != 1) {
//        fprintf(stderr, "Error loading server certificate from file");
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
    if (SSL_CTX_use_PrivateKey_file(ctx, _s_server_key, SSL_FILETYPE_PEM) < 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Fail during check private key. Error was: %s \n",
               ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_load_verify_locations(ctx, _s_trusted_cert, NULL)) {
        fprintf(stderr, "Failed to load SSL CA file: %s \n", _s_trusted_cert);
    } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        fprintf(stderr, "Error loading default CA file and/or directory");
        exit(EXIT_FAILURE);
    } else {
        printf("Using CA root certificates from file %s \n", _s_trusted_cert);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           verify_callback);
        SSL_CTX_set_verify_depth(ctx, 4);
    }
    SSL_CTX_set_info_callback(ctx, server_info_callback);
}

int main(int argc, char **argv)
{

    parse_args(argc, argv);

    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context(TLS_server_method());

    configure_context(ctx);

    sock = create_server_socket(_s_port);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            X509 *peer = NULL;
            if (peer = SSL_get_peer_certificate(ssl)) {
                if (SSL_get_verify_result(ssl) == X509_V_OK) {
                    printf("The client sent a certificate which verified OK \n");
                }
            }
            SSL_write(ssl, reply, strlen(reply));
            while (1) {
                int err = 0;
                char buf[1024] = {0};
                err = SSL_read(ssl, buf, 1024);
                if (err <= 0) {
                    fprintf(stderr, "Got error during read '%s' \n",
                            ERR_error_string(ERR_get_error(), NULL));
                    break;
                }
                printf("Read from client data '%s' with size '%d' \n", buf, err);
            }
        }

        SSL_free(ssl);
        close(client);
    }

    close(sock);
    cleanup_openssl();
}
