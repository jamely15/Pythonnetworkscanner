# Network Port Scanner Collection

## Overview

This repository contains three Python scripts for scanning network ports, ranging from a simple socket-based scanner to advanced Nmap-powered scanners with file and database output capabilities.

### Tools Included

1. **Simple Port Scanner (`app.py`)**
   - Scans a single IP address for open ports in a specified range.
   - Outputs results to a text file.
   - Uses only Python standard library (`socket`, `os`, `datetime`).

2. **Nmap Network Scanner (`sc.py`)**
   - Scans all hosts in a given CIDR network for open ports.
   - Uses the `python-nmap` library.
   - Supports scanning a range or "top ports".
   - Outputs results per host and a summary file.

3. **Nmap Scanner with MySQL Integration (`app 2.py`)**
   - Scans a CIDR network and saves results directly to a MySQL database.
   - Allows displaying all scan results from the database.
   - Uses `python-nmap` and `mysql-connector-python`.

---

## Setup Instructions

### 1. Clone the Repository

```sh
git clone https://github.com/<your-username>/network-port-scanner.git
cd network-port-scanner
```

### 2. Install Dependencies

All scripts require Python 3.6+.

Install required packages using pip:

```sh
pip install -r requirements.txt
```

**Note:**  
- `app.py` works with the standard library; no extra packages needed.
- `sc.py` and `app 2.py` require `python-nmap`.
- `app 2.py` requires `mysql-connector-python` and a running MySQL server.

### 3. Script Usage

#### **Simple Port Scanner (`app.py`)**

- Run the script:
  ```sh
  python app.py
  ```
- Enter target IP, port range, and output file name when prompted.

#### **Nmap Network Scanner (`sc.py`)**

- Ensure Nmap is installed on your system (`nmap` command available).
- Run the script:
  ```sh
  python sc.py
  ```
- Enter target network in CIDR format and port range ("start-end" or "top-ports").
- Results are saved in `scan_results_partial.txt` (per host) and `scan_results.txt` (summary).

#### **Nmap Scanner with MySQL (`app 2.py`)**

- Ensure MySQL is installed and running. Create a database and user for scanning results.
- Update `db_host`, `db_user`, `db_password`, and `db_name` in the script.
- Run the script:
  ```sh
  python "app 2.py"
  ```
- Enter target network and port range as prompted.
- Scan results are saved in the `scan_results` table.
- You can display results directly from the database.

---

## File Descriptions

- **app.py**  
  Basic port scanner using sockets. Quick, simple, and works for a single IP.

- **sc.py**  
  Advanced scanner for full networks using Nmap. Handles errors, saves incremental and full results.

- **app 2.py**  
  Like `sc.py`, but stores results in a MySQL database for persistent and queryable scan records.

---

## Requirements

See `requirements.txt` for Python dependencies.  
Nmap must be installed for scripts using `python-nmap` ([Download Nmap](https://nmap.org/download.html)).

MySQL must be installed and configured for `app 2.py`.

---

## Security Notes

- Scanning networks without authorization may violate laws or organizational policies.
- Always ensure you have permission before scanning.

---

## Contributing

Pull requests and issues are welcome! Please open a discussion for feature requests or bug reports.

---

## License

MIT License (see `LICENSE` file if provided).
