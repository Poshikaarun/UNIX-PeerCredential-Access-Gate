
# UNIX-Domain Socket Peer Credential Access Gate

## Introduction

This project implements a secure local client-server
communication system using UNIX-domain sockets.

The server authenticates clients using operating-system
peer credentials and controls access using role-based
authorization.

## Objectives

1. Implement AF_UNIX socket communication.
2. Authenticate clients using SO_PEERCRED.
3. Retrieve UID, GID and PID.
4. Implement role-to-operation access control.
5. Reject unauthorized clients.
6. Validate incoming requests.
7. Handle malformed messages and disconnects.
8. Maintain audit logs.
9. Apply socket permissions.

## Technologies

- C Programming Language
- Linux
- GCC Compiler
- UNIX-domain sockets
- SO_PEERCRED
- Python 3

## Role Policy

Admin:
READ, WRITE, DELETE

User:
READ, WRITE

Guest:
READ

Unauthorized:
No operations allowed.

## Project Execution

Compile:

make

Start server:

./server

Execute client:

./client READ admin

Other operations:

./client WRITE admin

./client DELETE admin

./client UNKNOWN admin

Run automated tests in another terminal:

python3 tests/test_client.py

## Audit Logging

The server records authentication decisions,
requests, authorization results and malformed
messages in logs/audit.log.

## Security Features

- OS-based peer authentication.
- UID-based role identification.
- Role-based access control.
- Socket file permissions.
- Request framing and validation.
- Unauthorized client rejection.
- Audit logging.
- Disconnect handling.

## Portability

This implementation is designed for Linux.

Linux supports SO_PEERCRED for retrieving
UNIX-domain socket peer credentials.

macOS and some BSD systems use getpeereid()
or other platform-specific mechanisms.

The current source code requires adaptation
for operating systems that do not support
the Linux SO_PEERCRED interface.

## Conclusion

The project demonstrates secure local
inter-process communication using UNIX-domain
sockets and peer credential authentication.

It provides role-based authorization and
audit logging to prevent unauthorized
operations.
