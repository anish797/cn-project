#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_PORT 65535

SSL_CTX *create_server_context(int port) {
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void handle_ssl_connection(SSL* ssl) {
    char data[1024];
    int bytes_received;

    printf("Connection from client\n");

    while ((bytes_received = SSL_read(ssl, data, sizeof(data))) > 0) {
        data[bytes_received] = '\0';
        printf("Received from client: %s\n", data);

        int port_start, port_stop;
        if (sscanf(data, "%d-%d", &port_start, &port_stop) == 2) {
            printf("Open ports received from client:");
            for (int port = port_start; port <= port_stop; port++) {
                printf(" %d", port);
            }
            printf("\n");

            const char *response = "Received open ports from client";
            SSL_write(ssl, response, strlen(response));

        } else {
            const char *response = "Received message";
            SSL_write(ssl, response, strlen(response));
        }

        memset(data, 0, sizeof(data));
    }

    if (bytes_received == 0) {
        printf("Connection closed by the client\n");
    } else if (bytes_received < 0) {
        int ssl_error = SSL_get_error(ssl, bytes_received);
        switch (ssl_error) {
            case SSL_ERROR_ZERO_RETURN:
                printf("SSL connection closed by the client (SSL_ERROR_ZERO_RETURN)\n");
                break;
            case SSL_ERROR_SYSCALL:
                perror("SSL_read error");
                break;
            default:
                fprintf(stderr, "SSL_read error: %d\n", ssl_error);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    printf("SSL connection closed\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int server_port = atoi(argv[1]);

    if (server_port <= 0 || server_port > MAX_PORT) {
        fprintf(stderr, "Invalid port number\n");
        exit(EXIT_FAILURE);
    }

    SSL_library_init();
    SSL_CTX *ctx = create_server_context(server_port);

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding socket");
        close(server_socket);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) == -1) {
        perror("Error listening for connections");
        close(server_socket);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", server_port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);

        if (client_socket == -1) {
            perror("Error accepting connection");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            SSL_free(ssl);
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("Connection from %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        handle_ssl_connection(ssl);
        close(client_socket);
    }

    close(server_socket);
    SSL_CTX_free(ctx);

    return 0;
}
