import sys
import socket
import argparse

ports = [21, 22, 25, 80, 443, 445, 3306, 5432, 6379, 8080]

parser = argparse.ArgumentParser(
    description="A custom TCP port scanner for reconnaissance."
)

# 2. Add the mandatory host argument
parser.add_argument("host", help="The target IP address or domain to scan")

# 3. Add the optional port argument using nargs='?'
parser.add_argument(
    "port",
    nargs="?",
    type=int,
    default=None,
    help="Optional single port to scan. If omitted, scans common ports.",
)

# 4. Parse the arguments from the command line
args = parser.parse_args()

# Now you can use them in your logic
print(f"Target Host: {args.host}")
if args.port:
    print(f"Scanning single specified port: {args.port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    result = s.connect_ex((args.host, args.port))

    if result == 0:
        print(f"[+] Port {args.port:5d} : is open")
    else:
        print(f"[-] Port {args.port:5d} : is closed")

    s.close()

else:
    print("No port provided. Running scan on common port list...")

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((args.host, port))
        if result == 0:
            print(f"[+] Port {port:5d} : is open")
        else:
            print(f"[-] Port {port:5d} : is closed")

    s.close()

print("\n[*] Scan Complete.")