import argparse
import asyncio
import sys

COMMON_PORTS = [21, 22, 25, 80, 443, 445, 3306, 5432, 6379, 8080]

async def scan_single_port(host, port, timeout=1.0):
    """Asynchronously checks if a single TCP port is open."""
    try:
        # Open connection with a strict timeout to ensure non-blocking speed
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        print(f"[+] Port {port:5d} : is open")
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        # Port is closed, filtered, or host is down
        print(f"[-] Port {port:5d} : is closed")
        return port, False

async def main():
    parser = argparse.ArgumentParser(
        description="High-performance asynchronous TCP port scanner."
    )
    parser.add_argument("host", help="The target IP address or domain to scan")
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=None,
        help="Optional single port to scan. If omitted, scans common ports.",
    )
    
    args = parser.parse_args()
    
    # Enforce strict boundary limits for port numbers
    if args.port and not (1 <= args.port <= 65535):
        print("[!] Error: Port number must be between 1 and 65535.", file=sys.stderr)
        sys.exit(1)

    print(f"Target Host: {args.host}")
    
    if args.port:
        print(f"Scanning single specified port: {args.port}")
        await scan_single_port(args.host, args.port)
    else:
        print(f"Running concurrent scan on {len(COMMON_PORTS)} common ports...")
        # Create a pool of concurrent tasks execution
        tasks = [scan_single_port(args.host, p) for p in COMMON_PORTS]
        # Run all tasks simultaneously
        await asyncio.gather(*tasks)

    print("\n[*] Scan Complete.")

if __name__ == "__main__":
    # Run the asynchronous event loop
    asyncio.run(main())