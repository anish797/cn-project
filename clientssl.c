#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_PORT 65535

SSL_CTX *init_ssl_context() {
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

SSL *create_ssl_connection(int sockfd, SSL_CTX *ctx) {
    SSL *ssl = SSL_new(ctx);

    if (ssl == NULL) {
        ERR_print_errors_fp(stderr);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    return ssl;
}

void send_receive_ssl_message(SSL *ssl, const char *message) {
    SSL_write(ssl, message, strlen(message));

    char response[1024];
    int bytes_received = SSL_read(ssl, response, sizeof(response));

    if (bytes_received == -1) {
        perror("Error receiving response");
        exit(EXIT_FAILURE);
    }

    response[bytes_received] = '\0';
    printf("Server response: %s\n", response);
}

int main() {
    char target_ip[16], message[1024];
    int port_start, port_stop;
    printf("Enter target IP address: ");
    scanf("%s", target_ip);
    printf("Enter starting port number: ");
    scanf("%d", &port_start);
    printf("Enter ending port number: ");
    scanf("%d", &port_stop);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    SSL_CTX *ssl_ctx = init_ssl_context();

    SSL *ssl = create_ssl_connection(sockfd, ssl_ctx);

    char open_ports_str[100];
    sprintf(open_ports_str, "%d-%d", port_start, port_stop);
    send_receive_ssl_message(ssl, open_ports_str);
    printf("Type message to send to server log: ");
    scanf(" %[^\n]", message);
    send_receive_ssl_message(ssl, message);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sockfd);

    return 0;
}


