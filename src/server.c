
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <stddef.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>

#define MAX_REQUEST 256
#define MAX_USERS 100

#define SOCKET_PATH "./run/peercred.sock"
#define POLICY_FILE "./config/policy.conf"
#define LOG_FILE "./logs/audit.log"

typedef struct {
    uid_t uid;
    char role[32];
} UserPolicy;

UserPolicy policies[MAX_USERS];
int policy_count = 0;

volatile sig_atomic_t stop_server = 0;

/* Handle Ctrl+C and termination signals */
void handle_signal(int sig)
{
    (void)sig;
    stop_server = 1;
}

/* Record security events in the audit log */
void audit_log(const char *message)
{
    FILE *fp = fopen(LOG_FILE, "a");

    if (fp == NULL) {
        perror("Audit log");
        return;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];

    if (tm_info != NULL) {
        strftime(timestamp, sizeof(timestamp),
                 "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strcpy(timestamp, "unknown-time");
    }

    fprintf(fp, "[%s] %s\n", timestamp, message);

    fclose(fp);
}

/* Check whether the role is valid */
int valid_role(const char *role)
{
    return strcmp(role, "admin") == 0 ||
           strcmp(role, "user") == 0 ||
           strcmp(role, "guest") == 0;
}

/* Load UID and role information from policy.conf */
int load_policy(const char *filename)
{
    FILE *fp = fopen(filename, "r");

    if (fp == NULL) {
        perror("Cannot open policy file");
        return -1;
    }

    char line[128];

    while (fgets(line, sizeof(line), fp)) {

        if (line[0] == '#' || line[0] == '\n')
            continue;

        unsigned long value;
        char role[32];
        char extra;

        if (sscanf(line, "%lu %31s %c",
                   &value, role, &extra) != 2) {

            fprintf(stderr, "Invalid policy entry: %s", line);

            fclose(fp);
            return -1;
        }

        if (value > (unsigned long)(uid_t)-1 ||
            !valid_role(role) ||
            policy_count >= MAX_USERS) {

            fprintf(stderr, "Invalid UID or role in policy.\n");

            fclose(fp);
            return -1;
        }

        /* Prevent duplicate UID entries */
        for (int i = 0; i < policy_count; i++) {

            if (policies[i].uid == (uid_t)value) {

                fprintf(stderr, "Duplicate UID in policy.\n");

                fclose(fp);
                return -1;
            }
        }

        policies[policy_count].uid = (uid_t)value;

        strcpy(policies[policy_count].role, role);

        policy_count++;
    }

    fclose(fp);

    if (policy_count == 0) {
        fprintf(stderr, "No valid policies found.\n");
        return -1;
    }

    printf("Loaded %d user policies.\n", policy_count);

    return 0;
}

/* Identify the role using the actual operating-system UID */
const char *get_role(uid_t uid)
{
    for (int i = 0; i < policy_count; i++) {

        if (policies[i].uid == uid)
            return policies[i].role;
    }

    return "unauthorized";
}

/* Apply role-to-operation access policy */
int is_allowed(const char *role, const char *operation)
{
    if (strcmp(role, "admin") == 0) {

        return strcmp(operation, "READ") == 0 ||
               strcmp(operation, "WRITE") == 0 ||
               strcmp(operation, "DELETE") == 0;
    }

    if (strcmp(role, "user") == 0) {

        return strcmp(operation, "READ") == 0 ||
               strcmp(operation, "WRITE") == 0;
    }

    if (strcmp(role, "guest") == 0) {

        return strcmp(operation, "READ") == 0;
    }

    return 0;
}

/* Send complete response to the client */
int send_response(int fd, const char *message)
{
    size_t length = strlen(message);
    size_t sent = 0;

    while (sent < length) {

        ssize_t n = send(fd, message + sent,
                         length - sent, MSG_NOSIGNAL);

        if (n < 0 && errno == EINTR)
            continue;

        if (n <= 0)
            return -1;

        sent += (size_t)n;
    }

    return 0;
}

/* Receive one newline-terminated request */
int receive_request(int fd, char *buffer, size_t size)
{
    size_t used = 0;

    while (used < size - 1) {

        char ch;

        ssize_t n = recv(fd, &ch, 1, 0);

        if (n == 0) {

            if (used == 0)
                return 0;   /* Client disconnected */

            return -1;      /* Incomplete request */
        }

        if (n < 0) {

            if (errno == EINTR)
                continue;

            return -1;
        }

        if (ch == '\n') {

            if (used == 0)
                return -1;  /* Empty request */

            buffer[used] = '\0';

            return 1;
        }

        if (ch == '\0' || ch == '\r')
            return -1;

        buffer[used++] = ch;
    }

    return -1;  /* Oversized request */
}

/* Authenticate, authorize and process one client */
void process_client(int client_fd)
{
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    /*
       Retrieve peer credentials from the operating system.
       Do not trust a username supplied by the client.
    */

    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
                   &credentials, &length) < 0 ||
        length != sizeof(credentials)) {

        audit_log("[FAIL] Peer credential retrieval failed");

        send_response(client_fd,
                      "ERROR: Authentication failed\n");

        return;
    }

    uid_t uid = credentials.uid;
    gid_t gid = credentials.gid;
    pid_t pid = credentials.pid;

    const char *role = get_role(uid);

    char log_message[512];

    snprintf(log_message, sizeof(log_message),
             "[AUTH] PID=%ld UID=%lu GID=%lu ROLE=%s",
             (long)pid,
             (unsigned long)uid,
             (unsigned long)gid,
             role);

    audit_log(log_message);

    printf("\nClient connected\n");
    printf("PID: %ld\n", (long)pid);
    printf("UID: %lu\n", (unsigned long)uid);
    printf("GID: %lu\n", (unsigned long)gid);
    printf("ROLE: %s\n", role);

    /*
       Reject unknown clients before reading requests.
    */

    if (strcmp(role, "unauthorized") == 0) {

        audit_log("[DENIED] Unknown UID rejected before request processing");

        send_response(client_fd,
                      "DENIED: Unauthorized client\n");

        return;
    }

    /*
       Set timeout to prevent indefinite waiting.
    */

    struct timeval timeout;

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) < 0) {

        audit_log("[FAIL] Unable to set receive timeout");

        send_response(client_fd,
                      "ERROR: Server configuration failure\n");

        return;
    }

    char request[MAX_REQUEST];

    int result = receive_request(client_fd,
                                 request, sizeof(request));

    if (result == 0) {

        audit_log("[INFO] Client disconnected without request");

        return;
    }

    if (result < 0) {

        audit_log("[FAIL] Malformed, incomplete or oversized request");

        send_response(client_fd,
                      "ERROR: Malformed request\n");

        return;
    }

    /*
       Request format:
       OPERATION|USERNAME

       Username is informational only.
       Authentication is based on the actual peer UID.
    */

    char *separator = strchr(request, '|');

    if (separator == NULL ||
        strchr(separator + 1, '|') != NULL ||
        separator == request ||
        separator[1] == '\0') {

        audit_log("[FAIL] Invalid request format");

        send_response(client_fd,
                      "ERROR: Invalid request format\n");

        return;
    }

    *separator = '\0';

    char *operation = request;
    char *username = separator + 1;

    if (strlen(operation) > 20 ||
        strlen(username) > 64) {

        audit_log("[FAIL] Request fields too long");

        send_response(client_fd,
                      "ERROR: Request fields too long\n");

        return;
    }

    /* Validate operation characters */
    for (char *p = operation; *p; p++) {

        if (*p < 'A' || *p > 'Z') {

            audit_log("[FAIL] Invalid operation characters");

            send_response(client_fd,
                          "ERROR: Invalid operation\n");

            return;
        }
    }

    /* Validate claimed username characters */
    for (char *p = username; *p; p++) {

        if (*p < 32 || *p > 126) {

            audit_log("[FAIL] Invalid username characters");

            send_response(client_fd,
                          "ERROR: Invalid username\n");

            return;
        }
    }

    snprintf(log_message, sizeof(log_message),
             "[REQUEST] UID=%lu OPERATION=%s CLAIMED_USERNAME=%s",
             (unsigned long)uid,
             operation,
             username);

    audit_log(log_message);

    /*
       Check whether the client's role permits
       the requested operation.
    */

    if (!is_allowed(role, operation)) {

        snprintf(log_message, sizeof(log_message),
                 "[DENIED] UID=%lu ROLE=%s OPERATION=%s",
                 (unsigned long)uid,
                 role,
                 operation);

        audit_log(log_message);

        printf("[DENIED] Operation %s rejected for %s\n",
               operation, role);

        send_response(client_fd,
                      "DENIED: Operation not permitted\n");

        return;
    }

    /*
       Authorized operation.
       Operations are simulated for this assignment.
    */

    snprintf(log_message, sizeof(log_message),
             "[PASS] UID=%lu ROLE=%s OPERATION=%s",
             (unsigned long)uid,
             role,
             operation);

    audit_log(log_message);

    printf("[PASS] %s authorized for %s\n",
           role, operation);

    char response[128];

    snprintf(response, sizeof(response),
             "SUCCESS: %.20s operation completed for role %.20s\n",
             operation, role);

    send_response(client_fd, response);
}

/* Main server function */
int main(int argc, char *argv[])
{
    const char *socket_path =
        argc > 1 ? argv[1] : SOCKET_PATH;

    const char *policy_path =
        argc > 2 ? argv[2] : POLICY_FILE;

    struct sockaddr_un address;

    if (strlen(socket_path) >= sizeof(address.sun_path)) {

        fprintf(stderr, "Socket path too long.\n");

        return 1;
    }

    /* Create required directories */
    if (mkdir("./run", 0755) < 0 && errno != EEXIST) {

        perror("Creating run directory");

        return 1;
    }

    if (mkdir("./logs", 0700) < 0 && errno != EEXIST) {

        perror("Creating logs directory");

        return 1;
    }

    /* Load access-control policy */
    if (load_policy(policy_path) < 0)
        return 1;

    /* Create UNIX-domain stream socket */
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (server_fd < 0) {

        perror("Socket creation failed");

        return 1;
    }

    memset(&address, 0, sizeof(address));

    address.sun_family = AF_UNIX;

    strcpy(address.sun_path, socket_path);

    /*
       Check for an existing socket.
       Never delete a regular file accidentally.
    */

    struct stat st;

    int stat_result = lstat(socket_path, &st);

    if (stat_result == 0) {

        if (!S_ISSOCK(st.st_mode)) {

            fprintf(stderr, "Socket path is not a socket.\n");

            close(server_fd);

            return 1;
        }

        if (unlink(socket_path) < 0) {

            perror("Removing old socket");

            close(server_fd);

            return 1;
        }

    } else if (errno != ENOENT) {

        perror("Checking socket path");

        close(server_fd);

        return 1;
    }

    /* Bind socket to filesystem path */
    if (bind(server_fd, (struct sockaddr *)&address,
             offsetof(struct sockaddr_un, sun_path) +
             strlen(socket_path) + 1) < 0) {

        perror("Bind failed");

        close(server_fd);

        return 1;
    }

    /* Set socket permissions */
    if (chmod(socket_path, 0660) < 0) {

        perror("Socket permission error");

        close(server_fd);

        unlink(socket_path);

        return 1;
    }

    /* Listen for incoming connections */
    if (listen(server_fd, 10) < 0) {

        perror("Listen failed");

        close(server_fd);

        unlink(socket_path);

        return 1;
    }

    /* Register signal handlers */
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = handle_signal;

    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT, &sa, NULL);

    sigaction(SIGTERM, &sa, NULL);

    printf("\n====================================\n");
    printf(" UNIX PEER CREDENTIAL ACCESS GATE\n");
    printf("====================================\n");

    printf("Socket: %s\n", socket_path);

    printf("Server PID: %ld\n", (long)getpid());

    printf("Waiting for clients...\n");

    audit_log("[START] Access Gate server started");

    /*
       Accept and process client connections.
    */

    while (!stop_server) {

        int client_fd = accept(server_fd, NULL, NULL);

        if (client_fd < 0) {

            if (errno == EINTR)
                continue;

            perror("Accept failed");

            break;
        }

        process_client(client_fd);

        close(client_fd);
    }

    /* Graceful shutdown */
    audit_log("[STOP] Access Gate server stopped");

    close(server_fd);

    unlink(socket_path);

    printf("\nServer stopped safely.\n");

    return 0;
}
