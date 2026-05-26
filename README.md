# Port-Scanner

A high-performance, asynchronous IPv4 TCP port scanner written in Python. Designed for speed, memory efficiency, and professional workflows.

## Features

* **High-Speed Asynchronous I/O:** Built on `asyncio` to handle thousands of concurrent connections in a single thread.
* **Producer/Consumer Architecture:** Memory-efficient queue design ensures low RAM usage, regardless of scan size.
* **Smart Banner Grabbing:** Optional service identification with HTTP-aware probing.
* **UNIX Pipeline Ready:** Separates scan results (`stdout`) from logs and progress bars (`stderr`).
* **Dynamic Resource Awareness:** Automatically scales concurrency to fit your OS file descriptor limits.
* **Pacing & Throttling:** Built-in delay controls to bypass basic rate-limiting/IDS triggers.

## Prerequisites

* Python 3.7+
* No external dependencies (uses standard library only).

## Installation

Clone the repository:

```bash
git clone https://github.com/babekasadli/Port-Scanner.git
cd Port-Scanner

```

## Usage

Basic scan:

```bash
python scanner.py -t 192.168.1.1 -p 1-1024

```

Advanced scan with banner grabbing and output redirection:

```bash
python scanner.py -t example.com -p 80,443,8000-8080 -b -c 500 > open_ports.txt

```

### Options

| Flag | Description |
| --- | --- |
| `-t, --target` | Target IPv4 address or hostname |
| `-p, --ports` | Port range or list (e.g., `80,443,1000-2000`) |
| `-c, --concurrency` | Max concurrent workers (Default: 1000) |
| `-T, --timeout` | Connection timeout in seconds (Default: 1.0) |
| `-d, --delay` | Dispatch delay between connections (seconds) |
| `-b, --banner` | Enable banner grabbing (service identification) |
| `-v, --verbose` | Show closed/filtered ports in the live feed |

## How it works

This script uses the **Producer/Consumer pattern** to maintain a fixed memory footprint. One "Producer" task manages the queue of ports, while a pool of "Consumer" workers processes connections. This ensures the system remains responsive even when scanning the entire 65,535 port range.

## Legal Disclaimer

This tool is for educational and authorized security auditing purposes only. Ensure you have explicit permission from the target owner before scanning. Unauthorized scanning may be illegal and against service terms of use.
