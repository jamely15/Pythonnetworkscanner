import nmap
import time
import ipaddress  # Import the ipaddress module

# Function to validate an IP address
def validate_ip(ip):
    parts = ip.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

# Function to validate a port range
def validate_port_range(port_range):
    try:
        start, end = map(int, port_range.split("-"))
        return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end
    except ValueError:
        return False

# Function to get user input for the target network and port range
def get_scan_details():
    while True:
        target_network = input("Enter target network in CIDR format (e.g., 192.168.1.0/24): ")
        if '/' in target_network and validate_ip(target_network.split('/')[0]):
            break
        print("Invalid network format. Please use CIDR notation (e.g., 192.168.1.0/24).")

    while True:
        port_range = input("Enter port range to scan (default: 1-65535 or 'top-ports'): ") or "1-65535"
        if port_range.lower() == "top-ports" or validate_port_range(port_range):
            break
        print("Invalid port range format. Please use the format 'start-end' (e.g., '22-80') or 'top-ports'.")

    return target_network, port_range

# Function to save partial scan results to a text file
def save_partial_results(host, results, filename="scan_results_partial.txt"):
    with open(filename, "a") as file:
        for proto in results.all_protocols():
            ports = sorted(results[proto].keys())
            for port in ports:
                state = results[proto][port]['state']
                service = results[proto][port].get('name', 'unknown service')
                file.write(f"{host:<20}{port:<10}{proto:<10}{state:<10}{service:<20}\n")
    print(f"Partial results saved for {host}.")

# Function to save full scan results to a text file
def save_to_file(scan_results, filename="scan_results.txt"):
    with open(filename, "w") as file:
        file.write("Scan Results:\n")
        file.write("-" * 60 + "\n")
        file.write(f"{'Target IP':<20}{'Port':<10}{'Protocol':<10}{'State':<10}{'Service':<20}\n")
        file.write("-" * 60 + "\n")
        
        for host in scan_results:
            for proto in scan_results[host].all_protocols():
                ports = sorted(scan_results[host][proto].keys())
                for port in ports:
                    state = scan_results[host][proto][port]['state']
                    service = scan_results[host][proto][port].get('name', 'unknown service')
                    file.write(f"{host:<20}{port:<10}{proto:<10}{state:<10}{service:<20}\n")
        
        file.write("-" * 60 + "\n")
    print(f"Full scan results saved to {filename}.")

# Function to run the scan
def run_scan(scanner, target_network, port_range):
    print(f"Starting scan on {target_network} for ports {port_range}...")
    start_time = time.time()

    # Generate a list of IP addresses in the specified network
    network = ipaddress.ip_network(target_network, strict=False)
    scan_results = {}

    try:
        for ip in network.hosts():  # Iterate over all usable IPs in the network
            try:
                # Use quick scan if 'top-ports' is selected
                if port_range.lower() == "top-ports":
                    scanner.scan(str(ip), arguments="-sS -T4 --top-ports 100 -Pn --max-retries 2 --host-timeout 30s")
                else:
                    scanner.scan(str(ip), port_range, arguments="-sS -T4 -Pn --max-retries 2 --host-timeout 30s")

                if scanner.has_host(str(ip)):
                    scan_results[str(ip)] = scanner[str(ip)]  # Store results if host is detected
                    save_partial_results(str(ip), scanner[str(ip)])  # Save partial results
            except Exception as ip_error:
                print(f"Error scanning {ip}: {ip_error}")
    except Exception as e:
        print(f"Error occurred during scan: {e}")
        return None

    end_time = time.time()
    scan_duration = end_time - start_time
    print(f"Scan completed in {scan_duration:.2f} seconds.")

    return scan_results


# Main function
def main():
    scanner = nmap.PortScanner()

    target_network, port_range = get_scan_details()

    scan_results = run_scan(scanner, target_network, port_range)

    if scan_results:
        save_to_file(scan_results)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")