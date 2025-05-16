import socket
import threading
import os
import argparse
import sys

# Change the name of the tool
TOOL_NAME = "Tunnel"
VERSION = "1.0"

# Use a port range to avoid conflicts with common services
DEFAULT_PORT_RANGE_START = 6000
DEFAULT_PORT_RANGE_END = 6100
MAX_CONNECTION_RETRY = 3

# Error codes for better handling
ERR_FILE_NOT_FOUND = 1
ERR_CONNECTION_FAILED = 2
ERR_INVALID_IP = 3
ERR_INVALID_PORT = 4
ERR_RECEIVE_FAILED = 5
ERR_SEND_FAILED = 6
ERR_FILE_EXISTS = 7
ERR_INVALID_CHOICE = 8
ERR_PEER_DISCONNECTED = 9
ERR_SOCKET_ERROR = 10
ERR_INVALID_ARGUMENT = 11

# Improved error messages
ERROR_MESSAGES = {
    ERR_FILE_NOT_FOUND: "Error: File not found.",
    ERR_CONNECTION_FAILED: "Error: Connection failed.",
    ERR_INVALID_IP: "Error: Invalid IP address.",
    ERR_INVALID_PORT: "Error: Invalid port number.",
    ERR_RECEIVE_FAILED: "Error: Failed to receive data.",
    ERR_SEND_FAILED: "Error: Failed to send data.",
    ERR_FILE_EXISTS: "Error: File already exists.",
    ERR_INVALID_CHOICE: "Error: Invalid choice. Please enter 'send' or 'receive'.",
    ERR_PEER_DISCONNECTED: "Error: Peer disconnected unexpectedly.",
    ERR_SOCKET_ERROR: "Error: Socket error occurred.",
    ERR_INVALID_ARGUMENT: "Error: Invalid argument."
}


def get_free_port(host, port_range_start, port_range_end):
    """
    Finds a free port within a specified range on the given host.

    Args:
        host (str): The hostname or IP address to check.
        port_range_start (int): The starting port number of the range.
        port_range_end (int): The ending port number of the range.

    Returns:
        int: A free port number, or 0 if none is found.
    """
    for port in range(port_range_start, port_range_end + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((host, port))
            s.close()
            return port
        except socket.error:
            pass  # Port is in use
    return 0  # No free port found


def send_file(host, port, file_path):
    """
    Sends a file to the specified host and port.

    Args:
        host (str): The IP address of the receiver.
        port (int): The port number to send to.
        file_path (str): The path to the file to send.

    Returns:
        int: 0 on success, error code on failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    except socket.error as e:
        print(f"{ERROR_MESSAGES[ERR_CONNECTION_FAILED]} {e}")
        return ERR_CONNECTION_FAILED

    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        print(f"{ERROR_MESSAGES[ERR_FILE_NOT_FOUND]}: {file_path}")
        return ERR_FILE_NOT_FOUND

    filename = os.path.basename(file_path)
    # Send filename and filesize first
    try:
        sock.sendall(f"{filename}:{file_size}".encode())
        # Wait for acknowledgement from receiver
        ack = sock.recv(1024).decode()
        if ack != "OK":
            print(f"{ERROR_MESSAGES[ERR_CONNECTION_FAILED]}: Receiver did not acknowledge filename/size.")
            sock.close()
            return ERR_CONNECTION_FAILED

        with open(file_path, "rb") as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                sock.sendall(data)
        print(f"[+] File '{filename}' sent successfully.")
    except socket.error as e:
        print(f"{ERROR_MESSAGES[ERR_SEND_FAILED]}: {e}")
        sock.close()
        return ERR_SEND_FAILED
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        sock.close()
        return ERR_SEND_FAILED
    sock.close()
    return 0



def receive_file(host, port, output_dir):
    """
    Receives a file on the specified host and port, and saves it to the output directory.

    Args:
        host (str): The IP address to listen on.
        port (int): The port number to listen on.
        output_dir (str): The directory to save the received file.

    Returns:
        int: 0 on success, error code on failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((host, port))
        sock.listen(1)  # Listen for one connection
        conn, addr = sock.accept()
        print(f"[+] Connection established with {addr[0]}:{addr[1]}")
    except socket.error as e:
        print(f"{ERROR_MESSAGES[ERR_CONNECTION_FAILED]}: {e}")
        return ERR_CONNECTION_FAILED

    try:
        # Receive filename and filesize
        filename_size = conn.recv(1024).decode()
        if not filename_size:
            conn.close()
            sock.close()
            print(f"{ERROR_MESSAGES[ERR_RECEIVE_FAILED]}: No filename/size received.")
            return ERR_RECEIVE_FAILED

        filename, filesize_str = filename_size.split(":")
        try:
            filesize = int(filesize_str)
        except ValueError:
            conn.close()
            sock.close()
            print(f"{ERROR_MESSAGES[ERR_RECEIVE_FAILED]}: Invalid filesize format.")
            return ERR_RECEIVE_FAILED

        # Acknowledge receipt of filename and size
        conn.sendall("OK".encode())

        filepath = os.path.join(output_dir, filename)
        # Check if file exists
        if os.path.exists(filepath):
            print(f"{ERROR_MESSAGES[ERR_FILE_EXISTS]}: {filepath}")
            conn.close()
            sock.close()
            return ERR_FILE_EXISTS

        with open(filepath, "wb") as f:
            received_size = 0
            while received_size < filesize:
                data = conn.recv(1024)
                if not data:
                    conn.close()
                    sock.close()
                    print(f"{ERROR_MESSAGES[ERR_PEER_DISCONNECTED]}")
                    return ERR_PEER_DISCONNECTED
                f.write(data)
                received_size += len(data)
                print(f"[+] Received {received_size}/{filesize} bytes")
        print(f"[+] File '{filename}' received successfully.")
    except socket.error as e:
        print(f"{ERROR_MESSAGES[ERR_RECEIVE_FAILED]}: {e}")
        conn.close()
        sock.close()
        return ERR_RECEIVE_FAILED
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        conn.close()
        sock.close()
        return ERR_RECEIVE_FAILED

    conn.close()
    sock.close()
    return 0



def main():
    """
    Main function to run the Tunnel file sharing tool.
    """
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} - Your Secure File Transfer Tool")
    parser.add_argument("mode", choices=['send', 'receive'], help="Mode of operation: 'send' a file or 'receive' a file.")
    parser.add_argument("host", type=str, help="IP address of the sender/receiver.  Use '0.0.0.0' to receive.")
    parser.add_argument("file_path", type=str, help="Path to the file to send, or the directory to save received files.")
    parser.add_argument("-p", "--port", type=int, help=f"Port number to use (default: auto-find in range {DEFAULT_PORT_RANGE_START}-{DEFAULT_PORT_RANGE_END}).", default=0)

    args = parser.parse_args()
    mode = args.mode
    host = args.host
    file_path = args.file_path
    port = args.port

    # Validate IP address
    try:
        socket.inet_aton(host)  # Check if it's a valid IP address
    except socket.error:
        print(f"{ERROR_MESSAGES[ERR_INVALID_IP]}")
        sys.exit(ERR_INVALID_IP)

    # Validate port
    if port != 0 and (port < 1 or port > 65535):
        print(f"{ERROR_MESSAGES[ERR_INVALID_PORT]}")
        sys.exit(ERR_INVALID_PORT)

    if port == 0:
        port = get_free_port(host, DEFAULT_PORT_RANGE_START, DEFAULT_PORT_RANGE_END)
        if port == 0:
            print(f"{ERROR_MESSAGES[ERR_CONNECTION_FAILED]}: No free port found in range {DEFAULT_PORT_RANGE_START}-{DEFAULT_PORT_RANGE_END}")
            sys.exit(ERR_CONNECTION_FAILED)
        print(f"[*] Using port: {port}")

    if mode == "send":
        if not os.path.exists(file_path):
            print(f"{ERROR_MESSAGES[ERR_FILE_NOT_FOUND]}: {file_path}")
            sys.exit(ERR_FILE_NOT_FOUND)
        result = send_file(host, port, file_path)
        if result != 0:
            sys.exit(result)
    elif mode == "receive":
        if not os.path.isdir(file_path):
            print(f"{ERROR_MESSAGES[ERR_FILE_NOT_FOUND]}: {file_path} is not a directory.  Please provide a valid output directory.")
            sys.exit(ERR_FILE_NOT_FOUND)
        result = receive_file(host, port, file_path)
        if result != 0:
            sys.exit(result)
    else:
        print(f"{ERROR_MESSAGES[ERR_INVALID_CHOICE]}")
        sys.exit(ERR_INVALID_CHOICE)

    print("[+] Operation completed.")
    sys.exit(0)



if __name__ == "__main__":
    main()
