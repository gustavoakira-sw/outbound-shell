# Reverse terminal access tool

This project provides a basic solution for remote terminal access to client machines via a central server using encrypted JSON messages sent and received over TCP sockets.

The client application runs on the remote machine and connects to the central server. The administrator then uses the server application to send commands to connected clients and receive their output.

This can be used when access to client machines is limited (no SSH) or if installation of reverse shells is not viable.

**Note:** You *will* need a server/laptop that can be reached by the client.

## Architecture

The system consists of two main components:

1.  **server (`server.py`):** Listens for incoming client connections, manages connected clients, and provides a command-line interface for the administrator to send commands and view output.
2.  **client (`client.py`):** Connects to the central server, receives commands, executes them locally using `subprocess`, and sends the output back to the server.

## Communication protocol

A simple JSON-based protocol over TCP sockets is used for communication between the server and clients.

*   **command message (server to client):**

    ```json
    {
        "type": "command",
        "command": "ls -la"
    }
    ```

*   **output message (client to server):**

    ```json
    {
        "type": "output",
        "output": "total 0\ndrwxr-xr-x  2 user  staff   64 Jan  1 10:00 .\ndrwxr-xr-x  2 user  staff   64 Jan  1 10:00 .."
    }
    ```

## Setup and usage

### Prerequisites

*   Python 3.x installed on both the server and client machines.
*   `openssl` for generating certificates on the server.

### 1. Generate self-signed certificates

On your server machine, open a terminal and run the following commands to generate a private key (`server.key`) and a self-signed certificate (`server.crt`):

```bash
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365
```

When prompted for "Common Name (e.g., server FQDN or YOUR name)", enter the **IP address or hostname** of your server.

Ensure that both `server.key` and `server.crt` are in the same directory as your `server.py` and `client.py` files on both the server and client machines.

### 2. Run the applications

#### Start the server (`server.py`)

On your server machine, open a terminal and run:

```bash
python3 server.py
```

You will see output similar to:

```
--- Remote Terminal Access Server ---
Commands:
  list                - List all connected clients
  select <client_id>  - Select a client to send commands to
  unselect            - Unselect the current client
  exit                - Shut down the server
  <command>           - Send command to selected client (or client_id:command)
-------------------------------------
[*] Listening securely on 0.0.0.0:12345
```

#### Start the client (`client.py`)

On each client machine you wish to control, open a terminal and run:

```bash
python3 client.py
```

Once a client connects, the server terminal will show messages about the SSL handshake and client connection, and automatically select the new client. The client terminal will show `[*] Connected securely to server <SERVER_IP>:<PORT>`. If this does not happen, double check the .crt and .key files are placed in the same working directory of the script in the client machine.

### 3. Interact from the server

In the server terminal (where `server.py` is running), you can now send commands to the connected clients. The prompt will dynamically update to reflect the selected client (e.g., `user@hostname # `).

*   **`list`**: List all connected clients and their IDs.
*   **`select <client_id>`**: Select a specific client to send commands to. The prompt will change to `user@hostname # `.
*   **`unselect`**: Deselect the current client. The prompt will revert to `Enter command (client_id:command): `.
*   **`<command>`**: Send a command to the currently selected client. For example, `ls -la`.
*   **`<client_id>:<command>`**: Send a command to a specific client without explicitly selecting it. For example, `1:pwd`.
*   **`exit`**: Shut down the server.

## Troubleshooting

If you encounter `SSL Handshake failed` errors, ensure:

*   The `server.crt` and `server.key` files are correctly placed and accessible to both `server.py` and `client.py`.
*   The Common Name entered when generating `server.crt` matches the `SERVER_HOST` IP address configured in `client.py`.
*   There are no firewall rules blocking the `SERVER_PORT` on the server machine.
