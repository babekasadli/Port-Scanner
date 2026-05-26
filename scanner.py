import argparse
import sys
import socket

def get_arguments():
    parser = argparse.ArgumentParser(description="A simple TCP port scanner")
    parser.add_argument("-t", "--target", dest="target", help="Target IP address", required=True)
    parser.add_argument("-p", "--ports", dest="ports", help="Port range to scan (e.g., 1-1024)", default="1-1024")
    return parser.parse_args()

def scan_port(ip, port):
    # Create a new socket using the IPv4 address family and TCP protocol
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set a timeout of 1 second so the scanner doesn't hang on closed ports
    sock.settimeout(1)

    # connect_ex returns 0 if the connection was successful
    result = sock.connect_ex((ip, port))
    if result == 0:
        print(f"[+] Port {port} is OPEN")

    # Always close the socket after using it
    sock.close()

if __name__ == "__main__":
    options = get_arguments()
    target_ip = options.target

    # Parse the start and end ports from the input string
    start_port, end_port = map(int, options.ports.split('-'))

    print(f"[*] Scanning target {target_ip} from port {start_port} to {end_port}...\n")

    # Loop through the specified range and scan each port sequentially
    for port in range(start_port, end_port + 1):
        scan_port(target_ip, port)

    print("\n[*] Scan completed.")
