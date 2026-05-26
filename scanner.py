"""
An enterprise-grade, asynchronous IPv4 TCP port enumerator.
Features Producer/Consumer concurrency, true dispatch rate-limiting,
async DNS resolution, dynamic OS limits, and UNIX-pipeline-friendly logging.
"""

import argparse
import asyncio
import dataclasses
import logging
import os
import socket
import sys
import time

# Attempt to load Unix resource limits dynamically
try:
    import resource
    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    # Cap safely at 80% of the OS limit to leave room for standard I/O
    MAX_SAFE_CONCURRENCY = max(1, int(soft_limit * 0.8))
except ImportError:
    # Windows fallback (Proactor event loop can handle tens of thousands natively)
    MAX_SAFE_CONCURRENCY = 4096

# --- Constants ---
MIN_PORT = 1
MAX_PORT = 65535
DEFAULT_PORT_RANGE = "1-1024"
DEFAULT_CONCURRENCY = 1000  
DEFAULT_TIMEOUT = 1.0
DEFAULT_DELAY = 0.0

BANNER_READ_TIMEOUT = 0.5
BANNER_MAX_READ = 128
BANNER_DISPLAY_MAX = 60
PROGRESS_REFRESH_INTERVAL = 0.1
PROBE_PAYLOAD = b"\r\n\r\n"

# --- Setup Logging ---
# Configured to stderr so stdout (scan results) can be cleanly piped to files
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    stream=sys.stderr
)
log = logging.getLogger("port_scanner")


@dataclasses.dataclass
class ScanTracker:
    """Structured state tracker for scan progress."""
    scanned: int = 0
    total: int = 0
    last_update: float = dataclasses.field(default_factory=time.perf_counter)


def get_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="High-speed Asyncio Port Scanner")
    parser.add_argument("-t", "--target", dest="target", help="Target IPv4 address or hostname", required=True)
    parser.add_argument("-p", "--ports", dest="ports", help=f"Port range (e.g., 1-1024 or 80,443,100-200). Default: {DEFAULT_PORT_RANGE}", default=DEFAULT_PORT_RANGE)
    parser.add_argument("-c", "--concurrency", dest="concurrency", help=f"Max concurrent workers. Default: {DEFAULT_CONCURRENCY}", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("-T", "--timeout", dest="timeout", help=f"Socket timeout in seconds. Default: {DEFAULT_TIMEOUT}", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("-d", "--delay", dest="delay", help=f"Pacing delay between dispatching connections (seconds). Default: {DEFAULT_DELAY}", type=float, default=DEFAULT_DELAY)
    parser.add_argument("-b", "--banner", dest="grab_banner", help="Attempt to grab service banners (sends probe)", action="store_true")
    parser.add_argument("-v", "--verbose", dest="verbose", help="Show live output for closed/filtered ports", action="store_true")
    return parser.parse_args()


async def resolve_target(target: str) -> str:
    """Resolve a hostname asynchronously and strictly validate it as IPv4."""
    loop = asyncio.get_running_loop()
    try:
        results = await loop.getaddrinfo(target, None, family=socket.AF_INET)
        if not results:
            raise ValueError(f"No IPv4 addresses found for '{target}'.")
        
        resolved = results[0][4][0]
        if resolved != target:
            log.info(f"[*] Resolved {target} -> {resolved}")
        return resolved
    except socket.gaierror:
        raise ValueError(f"Could not resolve target: '{target}'.")
    except OSError as e:
        raise ValueError(f"Resolution error for '{target}': {e}")


def parse_port_range(ports_str: str) -> list[int]:
    """Parse comma-separated ports and ranges (e.g., '80,443,100-200')."""
    ports = set()
    try:
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                start_str, end_str = part.split('-', 1)
                start, end = int(start_str), int(end_str)
            else:
                start = end = int(part)
            
            if not (MIN_PORT <= start <= MAX_PORT and MIN_PORT <= end <= MAX_PORT):
                raise ValueError(f"Ports must be between {MIN_PORT} and {MAX_PORT}.")
            if start > end:
                raise ValueError("Start port must be less than or equal to end port.")
                
            ports.update(range(start, end + 1))
    except ValueError as e:
        raise ValueError(f"Invalid port format '{ports_str}': {e}")

    return sorted(list(ports))


def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


async def scan_port(ip: str, port: int, timeout: float, verbose: bool, grab_banner: bool, tracker: ScanTracker):
    """Core network logic. Single-threaded async, so no locks are required for UI/state updates."""
    message = ""
    should_print = False
    
    try:
        coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout)
        
        banner = ""
        if grab_banner:
            try:
                # HTTP-friendly probe to provoke client-first protocols
                writer.write(PROBE_PAYLOAD)
                await writer.drain()
                
                raw_banner = await asyncio.wait_for(reader.read(BANNER_MAX_READ), timeout=BANNER_READ_TIMEOUT)
                banner = raw_banner.decode('utf-8', errors='replace').strip()
                banner = banner.replace("\r", "").replace("\n", " ") 
            except (asyncio.TimeoutError, ConnectionResetError, OSError):
                pass
                
        writer.close()
        await writer.wait_closed()
        
        service = get_service_name(port)
        svc_label = f"({service})" if service else ""
        banner_label = f" -> [{banner[:BANNER_DISPLAY_MAX]}...]" if len(banner) > BANNER_DISPLAY_MAX else (f" -> [{banner}]" if banner else "")
        message = f"[+] Port {port:<5} {svc_label:<10} is OPEN {banner_label}"
        should_print = True

    except ConnectionRefusedError:
        if verbose:
            message = f"[-] Port {port:<5} is closed (refused)"
            should_print = True
    except asyncio.TimeoutError:
        if verbose:
            message = f"[~] Port {port:<5} is filtered (timeout)"
            should_print = True
    except OSError as e:
        message = f"[!] Port {port:<5} socket error: {e}"
        should_print = True
    except Exception as e:
        message = f"[!] Port {port:<5} unexpected error: {e}"
        should_print = True

    # --- UI Processing ---
    if should_print:
        if not verbose:
            sys.stderr.write("\r\033[2K")
            sys.stderr.flush()
        # Print actual results strictly to stdout for pipeline compatibility
        print(message, file=sys.stdout)
        sys.stdout.flush()

    tracker.scanned += 1
    current_time = time.perf_counter()
    
    # Smooth UI throttling written to stderr
    if not verbose and (current_time - tracker.last_update > PROGRESS_REFRESH_INTERVAL or tracker.scanned == tracker.total):
        tracker.last_update = current_time
        progress = f"[*] Progress: {tracker.scanned}/{tracker.total} ports scanned..."
        sys.stderr.write("\r" + progress)
        sys.stderr.flush()


async def consumer(queue: asyncio.Queue, target_ip: str, timeout: float, verbose: bool, grab_banner: bool, tracker: ScanTracker):
    """Worker task that pulls from the queue. Naturally capped by the number of spawned consumers."""
    while True:
        port = await queue.get()
        try:
            await scan_port(target_ip, port, timeout, verbose, grab_banner, tracker)
        except Exception as e:
            # Absolute failsafe so a catastrophic error doesn't kill the worker silently
            log.error(f"\r\033[2K[!] Fatal worker error on port {port}: {e}")
        finally:
            queue.task_done()


async def producer(queue: asyncio.Queue, ports: list[int], delay: float):
    """
    Feeds the queue. 
    By sleeping here, we control the exact dispatch rate of the entire program,
    preventing massive synchronized network bursts.
    """
    for port in ports:
        await queue.put(port)
        if delay > 0:
            await asyncio.sleep(delay)


async def run_scanner(options: argparse.Namespace):
    try:
        target_ip = await resolve_target(options.target)
    except ValueError as e:
        log.error(f"[-] {e}")
        sys.exit(1)

    try:
        ports = parse_port_range(options.ports)
    except ValueError as e:
        log.error(f"[-] {e}")
        sys.exit(1)
    
    concurrency = max(1, options.concurrency)
    if concurrency > MAX_SAFE_CONCURRENCY:
        log.warning(f"[*] Capping concurrency at {MAX_SAFE_CONCURRENCY} to prevent OS limits.")
        concurrency = MAX_SAFE_CONCURRENCY

    total_ports = len(ports)
    log.info(f"[*] Target: {target_ip} | Ports: {ports[0]}-{ports[-1]} ({total_ports} total)")
    log.info(f"[*] Workers: {concurrency} | Timeout: {options.timeout}s | Delay: {options.delay}s | Banners: {bool(options.grab_banner)}\n")

    # Bounded queue prevents memory bloating
    queue = asyncio.Queue(maxsize=concurrency * 2)
    tracker = ScanTracker(total=total_ports)

    start_time = time.perf_counter()

    # 1. Spawn fixed number of workers (Consumers)
    consumers = [
        asyncio.create_task(consumer(queue, target_ip, options.timeout, options.verbose, options.grab_banner, tracker))
        for _ in range(concurrency)
    ]

    # 2. Spawn the queue feeder (Producer)
    prod_task = asyncio.create_task(producer(queue, ports, options.delay))

    # 3. Wait for all ports to be queued, then wait for them to be processed
    await prod_task
    await queue.join()

    # 4. Safely kill the infinite-loop workers
    for c in consumers:
        c.cancel()
    await asyncio.gather(*consumers, return_exceptions=True)

    elapsed = time.perf_counter() - start_time

    if not options.verbose:
        sys.stderr.write("\r\033[2K")
        sys.stderr.flush()

    log.info(f"{'─' * 55}")
    log.info(f"[*] Scan complete in {elapsed:.2f} seconds.")
    log.info(f"{'─' * 55}")


def main():
    options = get_arguments()
    
    if options.timeout <= 0:
        log.error("[-] Timeout must be a positive number.")
        sys.exit(1)
    if options.delay < 0:
        log.error("[-] Delay must be zero or a positive number.")
        sys.exit(1)

    try:
        asyncio.run(run_scanner(options))
    except KeyboardInterrupt:
        log.warning("\n\n[-] Scan cancelled by user.")
        sys.exit(1)
    except RuntimeError as e:
        # Silently catch the legacy Windows Proactor teardown bug
        if sys.platform == "win32" and "Event loop is closed" in str(e):
            pass
        else:
            raise


if __name__ == "__main__":
    main()
