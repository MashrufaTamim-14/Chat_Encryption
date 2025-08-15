# 🔐 Encrypted Chat Application (RSA + AES)

This is a simple end-to-end encrypted chat application built using Python. It uses:
- **RSA (2048-bit)** for asymmetric encryption of the AES key
- **AES (256-bit in EAX mode)** for symmetric encryption of the actual messages

Communication is done over TCP using Python's built-in `socket` library.

---

## ✨ Features

- Peer-to-peer messaging over TCP
- RSA public key exchange
- AES-256 session key exchange via RSA
- Secure encrypted chat using AES
- Interactive command-line interface

---

## 📁 Project Structure

.
├── chat_app.py # Main application script
├── requirements.txt # Python dependencies
└── README.md # Project documentation


---

## 🛠️ Requirements

Only one external library is required:

```text
pycryptodome==3.20.0
```

pip install -r requirements.txt

Step 1: Clone the Repository
git clone https://github.com/yourusername/encrypted-chat-app.git
cd encrypted-chat-app

✅ Step 2: Install Dependencies
pip install -r requirements.txt

✅ Step 3: Run the Chat App on Two Terminals or Devices

Terminal 1 (Host):

python chat_app.py
# Choose: h (host)


Terminal 2 (Client):

python chat_app.py
# Choose: c (connect)
# Enter the host's IP address

🔑 Key Exchange Commands

During the chat, type these commands to establish encryption:

/keyexchange
Exchange RSA public keys between peers.

/aesexchange
Generate a new AES key, encrypt it using the peer’s RSA key, and send it securely.

Once both keys are exchanged, all subsequent messages will be encrypted.

🔒 Encryption Details

RSA (2048-bit) is used to encrypt and exchange the AES key.

AES (256-bit) in EAX mode ensures both confidentiality and authentication of the message.

Public keys and encrypted data are base64 encoded for transmission.

🧪 Example
You: /keyexchange
[>] Sent your public key
[+] Received public key

You: /aesexchange
[+] Received and decrypted AES key

You: Hello, how are you?
[Encrypted] Hello, how are you?






