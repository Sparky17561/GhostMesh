import socket
import threading
import sys
import concurrent.futures

PORT = 5555

def tcp_server():
    host = socket.gethostbyname(socket.gethostname())
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, PORT))
    server.listen(1)
    print(f"[🔌] Waiting for connection on {host}:{PORT} ...")

    conn, addr = server.accept()
    print(f"[✅] Connected to {addr[0]}")

    # Start message exchange threads
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

def send_msg(sock):
    try:
        while True:
            msg = input()
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

def scan_for_server(port=PORT, timeout=0.5):
    hostname = socket.gethostbyname(socket.gethostname())
    base_ip = '.'.join(hostname.split('.')[:3]) + '.'
    print(f"[🔍] Scanning subnet {base_ip}0/24 on port {port}...")

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
        futures = [executor.submit(try_connect, base_ip + str(i)) for i in range(1, 255)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(f"[✅] Found server at {result}")
                return result
    print("[❌] No server found.")
    return None

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ['server', 'client']:
        print("Usage:\n  python chat.py server\n  python chat.py client")
        return

    if sys.argv[1] == 'server':
        tcp_server()
    else:
        server_ip = scan_for_server()
        if not server_ip:
            print("Failed to find server.")
            return
        tcp_client(server_ip)

if __name__ == "__main__":
    main()
