import socket
import threading
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Configuration
PORT = 5000
BUFFER_SIZE = 4096

# Globals
peer_public_key = None
rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey().export_key()
aes_key = None

# Encryption utilities
def encrypt_rsa(message, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(message)

def decrypt_rsa(ciphertext):
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(ciphertext)

def encrypt_aes(message):
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher_aes.nonce + tag + ciphertext)

def decrypt_aes(ciphertext):
    raw = base64.b64decode(ciphertext)
    nonce = raw[:16]
    tag = raw[16:32]
    ct = raw[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()

# Networking
def listen_for_messages(sock):
    while True:
        data = sock.recv(BUFFER_SIZE)
        if not data:
            break
        try:
            message = data.decode()
            if message.startswith("PUBKEY:"):
                global peer_public_key, sent_own_pubkey
                peer_public_key = base64.b64decode(message[7:])
                print("[+] Received public key")
                if not sent_own_pubkey:
                    sock.sendall(f"PUBKEY:{base64.b64encode(rsa_public_key).decode()}".encode())
                    sent_own_pubkey = True  # Update this too
            elif message.startswith("AESKEY:"):
                encrypted_key = base64.b64decode(message[7:])
                global aes_key
                aes_key = decrypt_rsa(encrypted_key)
                print("[+] Received and decrypted AES key")
            elif aes_key:
                print("[Encrypted]", decrypt_aes(message))
            else:
                print("[Plain]", message)
        except Exception as e:
            print(f"[!] Error: {e}")

def send_message_loop(sock):
    global peer_public_key, aes_key, sent_own_pubkey
    sent_own_pubkey = False
    while True:
        msg = input("You: ")
        if msg == "/keyexchange":
            sock.sendall(f"PUBKEY:{base64.b64encode(rsa_public_key).decode()}".encode())
            sent_own_pubkey = True
            print("[>] Sent your public key")
        elif msg == "/aesexchange":
            if peer_public_key:
                key = get_random_bytes(32)
                global aes_key
                aes_key = key
                encrypted_key = encrypt_rsa(key, peer_public_key)
                sock.sendall(f"AESKEY:{base64.b64encode(encrypted_key).decode()}".encode())
            else:
                print("[!] Exchange public keys first.")
        elif aes_key:
            encrypted_msg = encrypt_aes(msg)
            sock.sendall(encrypted_msg)
        else:
            sock.sendall(msg.encode())

# Main logic
def main():
    choice = input("Host (h) or Connect (c)? ")
    if choice.lower() == 'h':
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", PORT))
        s.listen(1)
        print(f"[+] Waiting for connection on port {PORT}...")
        conn, addr = s.accept()
        print(f"[+] Connected by {addr}")
    else:
        ip = input("Enter host IP: ")
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((ip, PORT))
        print(f"[+] Connected to {ip}:{PORT}")

    recv_thread = threading.Thread(target=listen_for_messages, args=(conn,))
    send_thread = threading.Thread(target=send_message_loop, args=(conn,))

    recv_thread.start()
    send_thread.start()

    recv_thread.join()
    send_thread.join()

if __name__ == "__main__":
    main()
