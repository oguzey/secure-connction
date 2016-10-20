#include "common.h"

#define CLIENT_KEY_DEFAULT "/ssl-certificates/client/client-key.pem"
#define CLIENT_CERT_DEFAULT "/ssl-certificates/client/client-cert.pem"

static char *_s_client_key = NULL;
static char *_s_client_cert = NULL;
static char *_s_trusted_cert = NULL;
static int _s_port = -1;

static void print_usage(void)
{
    printf("Usage: ./secure-client [-p port] [-k /path/to/private/client/key.pem]"
           "[-s /path/to/client/cert.pem] [-c /path/to/ca/cert.pem]\n");
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
            _s_client_key = optarg;
            break;
        case 's':
            _s_client_cert = optarg;
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
        printf("Server port not provided. Use '%d' as default. \n", _s_port);
    }
    if (!_s_client_key) {
        _s_client_key = CLIENT_KEY_DEFAULT;
        printf("Private key was not provided. Use default path '%s'\n",
               _s_client_key);
    }
    if (!_s_client_cert) {
        _s_client_cert = CLIENT_CERT_DEFAULT;
        printf("Client certificate was not provided. Use default path '%s'\n",
               _s_client_cert);
    }
    if (!_s_trusted_cert) {
        _s_trusted_cert = CA_CERT_DEFAULT;
        printf("CA certificate was not provided. Use default path '%s'\n",
               _s_trusted_cert);
    }
}

static int create_client_socket(const char *server_ip, int server_port,
                                const char *our_ip)
{
    int fd;
    struct sockaddr_in addr, local_addr;

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = 0;
    local_addr.sin_addr.s_addr = inet_addr(our_ip);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = inet_addr(server_ip);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(fd, (struct sockaddr*)&local_addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr))) {
        perror("Unable connect to server");
        exit(EXIT_FAILURE);
    }
    return fd;
}

static void client_info_callback(const SSL* ssl, int where, int ret)
{
    info_callback(ssl, where, ret, "client");
}

static void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_load_verify_locations(ctx, _s_trusted_cert, NULL) != 1) {
        fprintf(stderr, "Error loading CA file and/or directory");
        goto fail;
    }
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        fprintf(stderr, "Error loading default CA file and/or directory");
        goto fail;
    }
//    if (SSL_CTX_use_certificate_chain_file(ctx, _s_client_cert) != 1)  {
//        fprintf(stderr, "Cannot use certificate '%s'. Error was: %s \n",
//                       _s_client_cert, ERR_error_string(ERR_get_error(), NULL));
//        goto fail;
//    }

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, _s_client_cert, SSL_FILETYPE_PEM) < 0) {
        fprintf(stderr, "Cannot use certificate '%s'. Error was: %s \n",
               _s_client_cert, ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, _s_client_key, SSL_FILETYPE_PEM) < 0 ) {
        fprintf(stderr, "Cannot use key '%s'. Error was: %s \n",
               _s_client_key, ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Fail during check private key. Error was: %s \n",
               ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_info_callback(ctx, client_info_callback);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE,
                       verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    return;

fail:
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static int do_client_loop(SSL *ssl)
{
    int err = 0;
    int nwritten = 0;
    char buf[1024] = {'\0'};
    while (1) {
        if (!fgets(buf, sizeof(buf), stdin)) {
			printf("No data was reading from stdin \n");
            break;
        }
        buf[strlen(buf) - 1] = '\0';
        if (strlen(buf) == 0) {
            break;
        }
        printf("Read data from stdin: '%s' with size %lu\n", buf, strlen(buf));
        for (nwritten = 0; nwritten < strlen(buf); nwritten += err) {
            err = SSL_write(ssl, buf + nwritten, strlen(buf) - nwritten);
            if (err <= 0) {
                fprintf(stderr, "Got error while SSL_write '%s'\n",
                        ERR_error_string(ERR_get_error(), NULL));
                return 0;
            }
        }
    }
    return 1;
}

int main(int argc, char **argv)
{
    parse_args(argc, argv);

    int fd = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char buf[BUFSIZ] = {0};

    init_openssl();
    fd = create_client_socket("127.0.0.1", _s_port, "127.0.0.2");
    ctx = create_context(TLS_client_method());
    configure_context(ctx);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_read(ssl, buf, BUFSIZ) > 0) {
        fprintf(stdout, "Read form server '%s' \n", buf);
    } else {
        ERR_print_errors_fp(stderr);
    }
    if (do_client_loop(ssl)) {
        SSL_shutdown(ssl);
    } else {
        SSL_clear(ssl);
    }
	printf("Shutting down... \n");
    SSL_free(ssl);
    close(fd);

    cleanup_openssl();

}
