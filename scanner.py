import argparse
import sys
import socket

def get_arguments():
    parser = argparse.ArgumentParser(description="A simple TCP port scanner")
    parser.add_argument("-t", "--target", dest="target", help="Target IP address", required=True)
    parser.add_argument("-p", "--ports", dest="ports", help="Port range to scan (e.g., 1-1024)", default="1-1024")
    return parser.parse_args()

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN")
        sock.close()
    except socket.gaierror:
        # This exception is raised for address-related errors, like an invalid hostname
        print("\n[-] Hostname could not be resolved.")
        sys.exit(1)
    except socket.error:
        # This catches general socket errors
        print("\n[-] Could not connect to server.")
        sys.exit(1)

if __name__ == "__main__":
    options = get_arguments()
    target_ip = options.target

    try:
        start_port, end_port = map(int, options.ports.split('-'))
    except ValueError:
        print("[-] Invalid port format. Please use start-end (e.g., 1-1024)")
        sys.exit(1)

    print(f"[*] Scanning target {target_ip} from port {start_port} to {end_port}...\n")

    try:
        for port in range(start_port, end_port + 1):
            scan_port(target_ip, port)
    except KeyboardInterrupt:
        # This catches the Ctrl+C signal from the user
        print("\n[-] Scan canceled by user. Exiting...")
        sys.exit(1)

    print("\n[*] Scan completed.")
