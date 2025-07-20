import socket
import os
import time
from datetime import datetime

# Function to get user input for the target IP, port range, and file name
def get_scan_details():
    target_ip = input("Enter target IP address (default: 127.0.0.1): ") or "127.0.0.1"
    port_range = input("Enter port range to scan (default: 1-65535): ") or "1-65535"
    file_name = input("Enter output file name (default: scan_results.txt): ") or "scan_results.txt"
    return target_ip, port_range, file_name

# Function to run the scan
def run_scan(target_ip, port_range):
    print(f"Starting scan on {target_ip} for ports {port_range}...")
    start_time = time.time()

    open_ports = []
    # Parse the port range
    try:
        start_port, end_port = map(int, port_range.split('-'))
    except ValueError:
        print("Invalid port range format. Please use 'start-end'.")
        return None, None

    # Scan the specified range of ports
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Set a timeout for the connection attempt
            result = sock.connect_ex((target_ip, port))  # Try to connect to the port
            if result == 0:
                open_ports.append(port)  # Port is open

    end_time = time.time()
    scan_duration = end_time - start_time
    print(f"Scan completed in {scan_duration:.2f} seconds.")

    return open_ports, scan_duration

# Function to save scan results to a file
def save_scan_results(target_ip, open_ports, file_name, scan_duration):
    # Check if the file already exists, append if it does
    file_mode = 'a' if os.path.exists(file_name) else 'w'

    with open(file_name, file_mode) as f:
        f.write(f"Open Ports on {target_ip} (Scan performed at {datetime.now()})\n")
        f.write(f"Scan duration: {scan_duration:.2f} seconds\n")
        f.write("-------------------------------\n")

        # Write the open ports to the file
        for port in open_ports:
            f.write(f"Port {port}: open\n")

        f.write("-------------------------------\n")

    print(f"Scan results saved to {file_name}")

# Main function to handle user input and run the scan
def main():
    # Get scan details from the user
    target_ip, port_range, file_name = get_scan_details()

    # Run the scan and get the results
    open_ports, scan_duration = run_scan(target_ip, port_range)

    if open_ports:
        # Save the scan results to the specified file
        save_scan_results(target_ip, open_ports, file_name, scan_duration)

if __name__ == "__main__":
    main()