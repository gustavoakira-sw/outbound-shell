import socket
import threading
import json
import sys
import ssl
import os
import tty
import termios
import select
import signal
import base64

# --- CONFIGURATION ---
# Set to True to use FQDN/public CA mode (Let's Encrypt, etc.)
USE_FQDN = True

# If using FQDN mode, set the cert/key paths for your public CA certs (Let's Encrypt)
# Just copy the fullchain.pem and privkey.pem files to the same directory as this script, otherwise you will get FileNotFoundError
FQDN_CERTFILE = './fullchain.pem'
FQDN_KEYFILE = './privkey.pem'

# If using self-signed mode, set the cert/key paths
SELF_CERTFILE = 'server.crt'
SELF_KEYFILE = 'server.key'

HOST = '0.0.0.0'    # Listen on all available interfaces
PORT = 12345        # Port to listen on

if USE_FQDN:
    CERTFILE = FQDN_CERTFILE
    KEYFILE = FQDN_KEYFILE
else:
    CERTFILE = SELF_CERTFILE
    KEYFILE = SELF_KEYFILE

# --- END CONFIGURATION ---

# Global dictionaries to manage connected clients and their information
active_clients = {}  # Stores client_id: client_socket mapping
client_details = {}  # Stores client_id: client_info (e.g., 'user@hostname')
client_events = {}   # Stores client_id: threading.Event for signaling
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

def handle_client(client_socket, addr, client_id, stop_event):
    """Handles the initial connection and info gathering for a client."""
    client_address = f"{addr[0]}:{addr[1]}"
    print(f"[*] Accepted connection from: {client_address} (Client ID: {client_id})")
    active_clients[client_id] = client_socket
    client_details[client_id] = client_address
    client_events[client_id] = stop_event

    try:
        # First message should be client info
        data = receive_message(client_socket)
        if data and data['type'] == 'info' and 'hostname' in data:
            client_details[client_id] = data['hostname']
            print(f"\n[*] Client {client_id} updated info: {data['hostname']}")
            sys.stdout.write(get_prompt_string())
            sys.stdout.flush()
        
        # Wait until an interactive session is requested
        stop_event.wait()

    except Exception as e:
        print(f"\n[*] Error with client {client_address} (Client ID: {client_id}) before interaction: {e}")
    finally:
        # This thread will now terminate, handing over control to the main thread
        print(f"\n[*] Handing over client {client_id} to interactive session.")

def get_prompt_string():
    """Returns the current prompt string based on selected client."""
    if selected_client_id and selected_client_id in client_details:
        return f"{client_details[selected_client_id]} # "
    return "Enter command (client_id:command): "

selected_client_id = None # Track which client is currently selected for commands

def interactive_session(client_socket):
    """Handles an interactive PTY session with a client."""
    
    # Save old terminal settings
    old_settings = termios.tcgetattr(sys.stdin.fileno())
    
    def resize_handler(signum, frame):
        rows, cols = os.get_terminal_size()
        send_message(client_socket, {'type': 'resize', 'rows': rows, 'cols': cols})

    signal.signal(signal.SIGWINCH, resize_handler)

    try:
        # Set terminal to raw mode
        tty.setraw(sys.stdin.fileno())

        while True:
            r, w, e = select.select([client_socket, sys.stdin], [], [])

            if client_socket in r:
                # Data from client -> write to stdout
                message_length_raw = client_socket.recv(64)
                if not message_length_raw:
                    break
                message_length = int(message_length_raw.decode('utf-8').strip())
                message_raw = client_socket.recv(message_length)
                if not message_raw:
                    break
                
                data = json.loads(message_raw.decode('utf-8'))
                if data['type'] == 'pty_output':
                    sys.stdout.write(base64.b64decode(data['data']).decode('utf-8', 'replace'))
                    sys.stdout.flush()

            if sys.stdin in r:
                # Data from stdin -> send to client
                user_input = os.read(sys.stdin.fileno(), 1024)
                if user_input:
                    encoded_input = base64.b64encode(user_input).decode('utf-8')
                    send_message(client_socket, {'type': 'pty_input', 'data': encoded_input})
                else:
                    # Ctrl+D or similar
                    break
    
    finally:
        # Restore terminal settings
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
        signal.signal(signal.SIGWINCH, signal.SIG_DFL) # Restore default handler

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
            stop_event = threading.Event()
            client_handler = threading.Thread(target=handle_client, args=(secure_client_socket, addr, current_client_id, stop_event))
            client_handler.daemon = True
            client_handler.start()
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
    print("  interact <client_id> - Start an interactive session with a client")
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
        elif command_input.lower().startswith('interact '):
            try:
                client_id_to_select = int(command_input.split(' ')[1])
                if client_id_to_select in active_clients:
                    print(f"Starting interactive session with client: {client_details[client_id_to_select]}")
                    print("Press Ctrl+D (or your terminal's EOF character) to exit the session.")
                    
                    # Signal the handle_client thread to stop
                    client_events[client_id_to_select].set()
                    
                    client_socket = active_clients.pop(client_id_to_select)
                    
                    interactive_session(client_socket)
                    
                    print("\nSession ended.")
                    if client_id_to_select in client_details:
                        del client_details[client_id_to_select]
                    if client_id_to_select in client_events:
                        del client_events[client_id_to_select]
                    
                    client_socket.close()
                    print(f"[*] Client {client_id_to_select} disconnected.")
                    selected_client_id = None
                else:
                    print(f"Client with ID {client_id_to_select} not found.")
            except (IndexError, ValueError):
                print("Invalid interact command. Use 'interact <client_id>'.")
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

            if command_input and selected_client_id and selected_client_id in active_clients:
                 print("Interactive mode is required. Use 'interact <client_id>'.")
            elif command_input:
                 print("No client selected. Use 'list' to see clients and 'interact <client_id>' to connect.")
