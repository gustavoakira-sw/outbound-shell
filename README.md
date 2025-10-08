# Interactive Reverse Shell with PTY

This project provides a fully interactive reverse shell for remote terminal access, enabling the use of full-screen applications like `tmux` and `vim`. Communication is encrypted and managed through a central server.

The client application runs on a remote machine, connects to the server, and spawns a pseudo-terminal (PTY). The administrator can then connect from the server to this PTY for a seamless, interactive session.

This is ideal for environments where SSH is unavailable but interactive access is required.

**Note:** You will need a server/laptop that can be reached by the client.

## Architecture

The system has been refactored to use a pseudo-terminal (PTY) architecture:

1.  **Server (`server.py`):** Listens for client connections, manages interactive sessions, and puts the local terminal into raw mode to relay all keystrokes.
2.  **Client (`client.py`):** Connects to the server, forks a child process, and creates a PTY with a shell (e.g., `bash`). It then relays all I/O between the PTY and the server.

## Communication Protocol

The communication protocol has been updated to support raw PTY data streams and terminal resizing events. All data payloads are Base64 encoded to ensure safe JSON transport.

*   **PTY Input (Server -> Client):**
    ```json
    {
        "type": "pty_input",
        "data": "<base64_encoded_user_input>"
    }
    ```

*   **PTY Output (Client -> Server):**
    ```json
    {
        "type": "pty_output",
        "data": "<base64_encoded_pty_output>"
    }
    ```

*   **Terminal Resize (Server -> Client):**
    ```json
    {
        "type": "resize",
        "rows": 24,
        "cols": 80
    }
    ```

## Setup and usage

### Prerequisites

*   Python 3.x installed on both the server and client machines.
*   `openssl` for generating certificates on the server (if using self-signed certificate mode).

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
  interact <client_id> - Start an interactive session with a client
  exit                - Shut down the server
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

In the server terminal (where `server.py` is running), you can now start an interactive session with any connected client.

*   **`list`**: List all connected clients and their IDs.
*   **`interact <client_id>`**: Start a fully interactive session with the specified client.
    *   Your terminal will go into raw mode, and all keystrokes will be sent to the remote shell.
    *   This supports `tmux`, `vim`, and other full-screen applications.
    *   Press `Ctrl+D` (or your terminal's EOF character) to exit the interactive session.
*   **`exit`**: Shut down the server.

## Troubleshooting

If you encounter `SSL Handshake failed` errors, ensure:

*   The `server.crt` and `server.key` files are correctly placed and accessible to both `server.py` and `client.py`.
*   The Common Name entered when generating `server.crt` matches the `SERVER_HOST` IP address configured in `client.py`.
*   There are no firewall rules blocking the `SERVER_PORT` on the server machine.
