#!/usr/bin/env python3
import socket
import threading
import sys
import concurrent.futures

PORT = 5555

# ─── Helpers ────────────────────────────────────────────────────────────
def get_local_ip():
    """
    Returns the first private‐network IP on this host,
    by checking all addresses for 10.*, 172.16–31.*, or 192.168.*.
    """
    try:
        # gethostbyname_ex returns (hostname, aliaslist, iplist)
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
    except:
        addrs = []
    # Check for IPv4 private ranges
    for ip in addrs:
        if ip.startswith("10.") or ip.startswith("192.168.") or \
           (ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31):
            return ip
    # Fallback to UDP trick if no private addr found
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"

# ─── Messaging ──────────────────────────────────────────────────────────
def send_msg(sock):
    try:
        while True:
            msg = input("> ")
            if msg.lower() in ['exit', 'quit']:
                break
            sock.sendall(msg.encode('utf-8'))
    except:
        print("[❌] Connection closed.")
    finally:
        sock.close()

def recv_msg(sock):
    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            print(f"\n📩 {data.decode('utf-8')}\n> ", end="")
    except:
        print("[❌] Disconnected from peer.")

# ─── TCP Server/Client ──────────────────────────────────────────────────
def tcp_server():
    host = get_local_ip()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, PORT))
    server.listen(1)
    print(f"[🔌] Waiting for connection on {host}:{PORT} ...")

    conn, addr = server.accept()
    print(f"[✅] Connected to {addr[0]}")

    threading.Thread(target=recv_msg, args=(conn,), daemon=True).start()
    send_msg(conn)

    conn.close()
    server.close()

def tcp_client(server_ip):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((server_ip, PORT))
        print(f"[✅] Connected to {server_ip}:{PORT}")
    except Exception as e:
        print(f"[❌] Connection failed: {e}")
        sys.exit(1)

    threading.Thread(target=recv_msg, args=(client,), daemon=True).start()
    send_msg(client)
    client.close()

# ─── Auto‑Discovery ──────────────────────────────────────────────────────
def scan_for_server(port=PORT, timeout=0.5):
    base = '.'.join(get_local_ip().split('.')[:3]) + '.'
    print(f"[🔍] Scanning subnet {base}0/24 on port {port}...")

    def try_connect(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return ip
        except:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(try_connect, base + str(i)) for i in range(1, 255)]
        for future in concurrent.futures.as_completed(futures):
            if (res := future.result()):
                print(f"[✅] Found server at {res}")
                return res

    print("[❌] No server found.")
    return None

# ─── Main Entry ─────────────────────────────────────────────────────────
def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ['server', 'client']:
        print("Usage:\n  python chat.py server\n  python chat.py client")
        sys.exit(1)

    if sys.argv[1] == 'server':
        tcp_server()
    else:
        server_ip = scan_for_server()
        if not server_ip:
            print("Failed to find server.")
            sys.exit(1)
        tcp_client(server_ip)

if __name__ == "__main__":
    main()
