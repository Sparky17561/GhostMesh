#!/usr/bin/env python3
"""
GhostMesh Laptop Client
- Connects as client to GhostMesh mobile server (Termux/iSH hotspot)
- Engages in chat (sends/receives messages)
- Auto-detects role-based prompts (/system, /medic, /mechanic) and generates LLM replies
"""
import socket
import sys
import os
import threading
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from llama_cpp import Llama

# ---------------- CONFIG ----------------
SERVER_IP = None  # set via args or prompt
PORT = 5555
BUFFER_SIZE = 8192
SALT = b"ghostmesh_salt"
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'DeepSeek-R1-Distill-Qwen-1.5B-Q4_K_M.gguf')

# Prompt templates (allow internal reasoning, but output only final answer)
TEMPLATES = {
    'system': """
You are GhostMesh System Assistant.
You may think through the solution silently, but only output the final concise answer.
Task: Provide direct answers (<=100 words) in bullet points; no reasoning.

Query:
{query}
""",

    'medic': """
You are a survival field medic.
Think through the steps internally, but output only a clear, numbered list of actions.
Format:
1. Immediate life-saving action
2. Secondary care action
3. Ongoing management
4. Evacuation steps

Scenario:
{query}
""",

    'mechanic': """
You are a combat field mechanic.
Silently consider the problem, then output only the numbered repair steps with tools and cautions.

Problem:
{query}
"""
}

# ---------- AES UTILITIES ----------
def derive_key(passphrase: str) -> bytes:
    return PBKDF2(passphrase, SALT, dkLen=32, count=100000)

def encrypt(msg: str, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
    return cipher.nonce + tag + ct

def decrypt(blob: bytes, key: bytes) -> str:
    nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode('utf-8')

# ---------- MESSAGE RECEIVER ----------
def receiver_loop(sock: socket.socket, aes_key: bytes, llm: Llama):
    while True:
        data = sock.recv(BUFFER_SIZE)
        if not data:
            print("[!] Connection closed by server.")
            break
        try:
            text = decrypt(data, aes_key)
        except Exception as e:
            print(f"[!] Decrypt error: {e}")
            continue
        print(f"\n<Remote> {text}\n> ", end="")

        for cmd in ('/system', '/medic', '/mechanic'):
            if cmd in text:
                role = cmd.lstrip('/')
                query = text.split(cmd, 1)[1].strip()
                prompt = TEMPLATES[role].format(query=query)
                print(f"[{role.upper()} prompt]")
                try:
                    resp = llm(
                        prompt,
                        max_tokens=512,
                        temperature=0.4,
                        top_p=0.9,
                        echo=False
                    )
                    full = resp['choices'][0]['text'].strip()
                    # Extract only what follows 'Answer:' if present
                    if 'Answer:' in full:
                        reply = full.split('Answer:', 1)[1].strip()
                    else:
                        reply = full
                    if not reply:
                        reply = "[LLM Error] empty response"
                except Exception as e:
                    reply = f"[LLM Error] {e}"
                auto_msg = f"[{role.capitalize()}] {reply}"
                sock.send(encrypt(auto_msg, aes_key))
                print(f"[{role.capitalize()} response sent]\n> ", end="")
                break

# ---------- MAIN ----------
def main():
    global SERVER_IP
    SERVER_IP = sys.argv[1] if len(sys.argv) >= 2 else input("Enter mobile server IP: ").strip()
    passphrase = sys.argv[2] if len(sys.argv) >= 3 else getpass("Enter GhostMesh passphrase: ")
    aes_key = derive_key(passphrase)

    print("[*] Loading LLM model...")
    try:
        llm = Llama(model_path=MODEL_PATH)
    except Exception as e:
        print(f"[!] Model load error: {e}")
        sys.exit(1)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, PORT))
        print(f"[*] Connected to {SERVER_IP}:{PORT}")
    except Exception as e:
        print(f"[!] Connection error: {e}")
        return

    threading.Thread(target=receiver_loop, args=(sock, aes_key, llm), daemon=True).start()

    try:
        while True:
            msg = input("> ").strip()
            if msg.lower() in ('/exit', 'quit'):
                break
            sock.send(encrypt(msg, aes_key))
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print("[*] Disconnected.")

if __name__ == '__main__':
    main()
