
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "./run/peercred.sock"

int main(int argc, char *argv[])
{
    if (argc < 2 || argc > 3) {

        printf("Usage: ./client OPERATION [USERNAME]\n");

        printf("Example: ./client READ admin\n");

        return 1;
    }

    const char *operation = argv[1];

    const char *username =
        argc == 3 ? argv[2] : "anonymous";

    if (strlen(operation) > 20 ||
        strlen(username) > 64 ||
        strlen(operation) == 0 ||
        strlen(username) == 0 ||
        strchr(operation, '|') ||
        strchr(username, '|') ||
        strchr(operation, '\n') ||
        strchr(username, '\n') ||
        strchr(operation, '\r') ||
        strchr(username, '\r')) {

        printf("Invalid input.\n");

        return 1;
    }

    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock_fd < 0) {

        perror("Socket creation failed");

        return 1;
    }

    struct sockaddr_un address;

    memset(&address, 0, sizeof(address));

    address.sun_family = AF_UNIX;

    strcpy(address.sun_path, SOCKET_PATH);

    if (connect(sock_fd, (struct sockaddr *)&address,
                offsetof(struct sockaddr_un, sun_path) +
                strlen(SOCKET_PATH) + 1) < 0) {

        perror("Connection failed");

        close(sock_fd);

        return 1;
    }

    char request[256];

    snprintf(request, sizeof(request),
             "%s|%s\n", operation, username);

    size_t length = strlen(request);

    size_t sent = 0;

    while (sent < length) {

        ssize_t n = send(sock_fd, request + sent,
                         length - sent, MSG_NOSIGNAL);

        if (n < 0 && errno == EINTR)
            continue;

        if (n <= 0) {

            perror("Send failed");

            close(sock_fd);

            return 1;
        }

        sent += (size_t)n;
    }

    char response[256];

    size_t received = 0;

    while (received < sizeof(response) - 1) {

        ssize_t n = recv(sock_fd,
                         response + received,
                         sizeof(response) - 1 - received,
                         0);

        if (n < 0 && errno == EINTR)
            continue;

        if (n < 0) {

            perror("Receive failed");

            close(sock_fd);

            return 1;
        }

        if (n == 0)
            break;

        received += (size_t)n;

        if (memchr(response, '\n', received) != NULL)
            break;
    }

    response[received] = '\0';

    printf("\n========== SERVER RESPONSE ==========\n");

    if (received > 0)
        printf("%s", response);
    else
        printf("Server disconnected without a response.\n");

    printf("=====================================\n");

    close(sock_fd);

    return 0;
}
