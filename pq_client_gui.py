# pq_client_gui.py
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox, scrolledtext

import socket
import threading
import base64
import os

import oqs  # Python bindings for liboqs: Kyber KEM, etc.
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Note to self: Adjust if oqs build uses a different name (e.g. "ML-KEM-512"):
KEM_ALG = "Kyber512"  # Kyber KEM algorithm name :contentReference[oaicite:3]{index=3}
AES_KEY_LEN = 32      # 256-bit AES key for AES-GCM


def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive a symmetric AES key from the Kyber shared secret using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LEN,
        salt=None,
        info=b"kyber-aes-chat-v1",
    )
    return hkdf.derive(shared_secret)


def aes_encrypt(aes_key: bytes, plaintext: str) -> str:
    """
    Encrypt plaintext with AES-GCM.
    Return Base64( nonce || ciphertext || tag ).
    cryptography's AESGCM.encrypt returns ciphertext||tag. :contentReference[oaicite:4]{index=4}
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    combined = nonce + ct_with_tag
    return base64.b64encode(combined).decode("ascii")


def aes_decrypt(aes_key: bytes, encoded: str) -> str:
    """
    Decrypt Base64( nonce || ciphertext || tag ) with AES-GCM.
    """
    data = base64.b64decode(encoded.encode("ascii"))
    nonce = data[:12]
    ct_with_tag = data[12:]
    aesgcm = AESGCM(aes_key)
    plaintext_bytes = aesgcm.decrypt(nonce, ct_with_tag, None)
    return plaintext_bytes.decode("utf-8")


def generate_kem_keypair():
    """
    Generate a Kyber keypair and return (public_key, secret_key).
    Uses oqs.KeyEncapsulation and export_secret_key(). :contentReference[oaicite:5]{index=5}
    """
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return public_key, secret_key


def decap_shared_secret(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Given a Kyber ciphertext and secret key, recover the shared secret.
    Tries import_secret_key() first, falls back to constructor injection
    for older oqs bindings. :contentReference[oaicite:6]{index=6}
    """
    try:
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            kem.import_secret_key(secret_key)
            shared_secret = kem.decap_secret(ciphertext)
    except AttributeError:
        with oqs.KeyEncapsulation(KEM_ALG, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


class KyberAESChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Kyber + AES Chat Client")

        # Network state
        self.SERVER_HOST = None
        self.SERVER_PORT = None
        self.client_socket = None
        self.receive_thread = None

        # IDs and crypto
        self.user_id = None
        # For each peer_id we store a symmetric AES key
        self.aes_keys = {}       # peer_id -> aes_key(bytes)
        # For handshakes we initiate: peer_id -> Kyber secret key
        self.pending_kem = {}    # peer_id -> secret_key(bytes)

        self._build_gui()

    def _build_gui(self):
        root = self.master

        main_frame = ttk.Frame(root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        server_frame = ttk.LabelFrame(main_frame, text="Server (Ngrok) Address")
        server_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
        server_frame.columnconfigure(1, weight=1)

        ttk.Label(server_frame, text="Ngrok Host:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.ngrok_host_entry = ttk.Entry(server_frame, width=25)
        self.ngrok_host_entry.insert(0, "0.tcp.ngrok.io")
        self.ngrok_host_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(server_frame, text="Port:").grid(
            row=0, column=2, padx=5, pady=5, sticky="e"
        )
        self.ngrok_port_entry = ttk.Entry(server_frame, width=8)
        self.ngrok_port_entry.insert(0, "12345")
        self.ngrok_port_entry.grid(row=0, column=3, padx=5, pady=5)

        self.set_server_button = ttk.Button(
            server_frame, text="Set Server Address", command=self.set_server_address
        )
        self.set_server_button.grid(row=0, column=4, padx=10, pady=5)

        user_frame = ttk.LabelFrame(main_frame, text="Your Identity")
        user_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        user_frame.columnconfigure(1, weight=1)

        ttk.Label(user_frame, text="Your userID:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.user_id_entry = ttk.Entry(user_frame, width=25)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.connect_button = ttk.Button(
            user_frame, text="Connect", command=self.connect_to_server
        )
        self.connect_button.grid(row=0, column=2, padx=10, pady=5)

        self.connection_status = ttk.Label(user_frame, text="Not connected.", foreground="red")
        self.connection_status.grid(row=1, column=0, columnspan=3, sticky="w", padx=5)

        chat_frame = ttk.LabelFrame(main_frame, text="Encrypted Chat")
        chat_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=5)
        main_frame.rowconfigure(2, weight=1)
        chat_frame.rowconfigure(1, weight=1)
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.columnconfigure(1, weight=0)
        chat_frame.columnconfigure(2, weight=0)

        ttk.Label(chat_frame, text="Recipient ID:").grid(
            row=0, column=0, padx=5, pady=5, sticky="w"
        )
        self.recipient_entry = ttk.Entry(chat_frame, width=20)
        self.recipient_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.keyx_button = ttk.Button(
            chat_frame, text="Run Key Exchange", command=self.start_key_exchange
        )
        self.keyx_button.grid(row=0, column=2, padx=5, pady=5)

        self.chat_area = scrolledtext.ScrolledText(
            chat_frame, width=60, height=18, state=tk.DISABLED
        )
        self.chat_area.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        self.message_entry = ttk.Entry(chat_frame)
        self.message_entry.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.send_button = ttk.Button(chat_frame, text="Send", command=self.send_message)
        self.send_button.grid(row=2, column=2, padx=5, pady=5)

    def set_server_address(self):
        host = self.ngrok_host_entry.get().strip()
        port = self.ngrok_port_entry.get().strip()

        if not host or not port:
            messagebox.showwarning("Warning", "Please enter both Ngrok host and port.")
            return
        if not port.isdigit():
            messagebox.showwarning("Warning", "Port must be numeric.")
            return

        self.SERVER_HOST = host
        self.SERVER_PORT = int(port)

        messagebox.showinfo(
            "Server address set",
            f"Server address set to {self.SERVER_HOST}:{self.SERVER_PORT}",
        )

        self.ngrok_host_entry.config(state=tk.DISABLED)
        self.ngrok_port_entry.config(state=tk.DISABLED)
        self.set_server_button.config(state=tk.DISABLED)

    def connect_to_server(self):
        if self.SERVER_HOST is None or self.SERVER_PORT is None:
            messagebox.showwarning("Warning", "Set server address first.")
            return

        user_id = self.user_id_entry.get().strip()
        if not user_id:
            messagebox.showwarning("Warning", "Please enter your userID.")
            return

        self.user_id = user_id

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.SERVER_HOST, self.SERVER_PORT))

            sock.sendall(self.user_id.encode("utf-8"))

            ack = sock.recv(1024).decode("utf-8", errors="ignore")
            self._append_chat_line(f"[SERVER] {ack}")

            self.client_socket = sock
            self.connection_status.config(text="Connected.", foreground="green")
            self.connect_button.config(state=tk.DISABLED)

            self.receive_thread = threading.Thread(
                target=self.receive_messages, daemon=True
            )
            self.receive_thread.start()

        except Exception as e:
            messagebox.showerror("Connection error", str(e))

    def start_key_exchange(self):
        if not self.client_socket:
            messagebox.showwarning("Warning", "Connect to server first.")
            return

        peer_id = self.recipient_entry.get().strip()
        if not peer_id:
            messagebox.showwarning("Warning", "Enter a recipient ID.")
            return
        if peer_id == self.user_id:
            messagebox.showwarning("Warning", "Recipient ID cannot be your own.")
            return

        try:
            public_key, secret_key = generate_kem_keypair()
        except Exception as e:
            messagebox.showerror("Key exchange error", f"KEM keypair failed: {e}")
            return

        self.pending_kem[peer_id] = secret_key

        pk_b64 = base64.b64encode(public_key).decode("ascii")
        payload = f"KEM_INIT:{pk_b64}"
        full_message = f"{peer_id}|{payload}"

        try:
            self.client_socket.sendall(full_message.encode("utf-8"))
            self._append_chat_line(
                f"[INFO] Sent KEM_INIT to {peer_id}. Waiting for KEM_RESP..."
            )
        except Exception as e:
            messagebox.showerror("Network error", f"Failed to send KEM_INIT: {e}")

    def send_message(self):
        if not self.client_socket:
            messagebox.showwarning("Warning", "Connect to server first.")
            return

        peer_id = self.recipient_entry.get().strip()
        if not peer_id:
            messagebox.showwarning("Warning", "Enter a recipient ID.")
            return
        if peer_id == self.user_id:
            messagebox.showwarning("Warning", "Recipient ID cannot be your own.")
            return

        plaintext = self.message_entry.get().strip()
        if not plaintext:
            messagebox.showwarning("Warning", "Message cannot be empty.")
            return

        aes_key = self.aes_keys.get(peer_id)
        if aes_key is None:
            messagebox.showwarning(
                "No shared key",
                f"No AES key established with {peer_id}. "
                f"Run 'Run Key Exchange' first.",
            )
            return

        try:
            encoded_cipher = aes_encrypt(aes_key, plaintext)
        except Exception as e:
            messagebox.showerror("Encryption error", f"AES-GCM failed: {e}")
            return

        payload = f"MSG:{encoded_cipher}"
        full_message = f"{peer_id}|{payload}"

        try:
            self.client_socket.sendall(full_message.encode("utf-8"))
            self.message_entry.delete(0, tk.END)
            self._append_chat_line(f"Me → {peer_id}: {plaintext}")
        except Exception as e:
            messagebox.showerror("Network error", f"Failed to send message: {e}")

    def receive_messages(self):
        """
        Background thread: receives messages from the server and handles:
          - KEM_INIT from a peer
          - KEM_RESP from a peer
          - MSG (encrypted text) from a peer
          - or plain text (server notices)
        """
        try:
            while True:
                if not self.client_socket:
                    break
                data = self.client_socket.recv(4096)
                if not data:
                    break

                message = data.decode("utf-8", errors="ignore")

                if "|" not in message:
                    self._append_chat_line(message)
                    continue

                sender_id, payload = message.split("|", 1)

                if payload.startswith("KEM_INIT:"):
                    self._handle_kem_init(sender_id, payload[len("KEM_INIT:"):])
                elif payload.startswith("KEM_RESP:"):
                    self._handle_kem_resp(sender_id, payload[len("KEM_RESP:"):])
                elif payload.startswith("MSG:"):
                    self._handle_encrypted_msg(sender_id, payload[len("MSG:"):])
                else:

                    self._append_chat_line(f"{sender_id}: {payload}")

        except Exception as e:
            self._append_chat_line(f"[ERROR] receive loop: {e}")
        finally:
            self._append_chat_line("[INFO] Disconnected from server.")
            self.connection_status.config(text="Disconnected.", foreground="red")
            try:
                if self.client_socket:
                    self.client_socket.close()
            except Exception:
                pass
            self.client_socket = None


    def _handle_kem_init(self, sender_id: str, pk_b64: str):
        """
        We are the responder: we receive the peer's Kyber public key,
        run encap_secret, derive AES key, and send back KEM_RESP.
        """
        try:
            public_key = base64.b64decode(pk_b64.encode("ascii"))
        except Exception:
            self._append_chat_line(
                f"[ERROR] Bad KEM_INIT from {sender_id}: invalid base64."
            )
            return

        try:
            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)

            aes_key = derive_aes_key(shared_secret)
            self.aes_keys[sender_id] = aes_key

            ct_b64 = base64.b64encode(ciphertext).decode("ascii")
            payload = f"KEM_RESP:{ct_b64}"
            full_message = f"{sender_id}|{payload}"

            if self.client_socket:
                self.client_socket.sendall(full_message.encode("utf-8"))

            self._append_chat_line(
                f"[KEYX] Established AES key with {sender_id} (as responder)."
            )
        except Exception as e:
            self._append_chat_line(
                f"[ERROR] KEM_INIT handling for {sender_id} failed: {e}"
            )

    def _handle_kem_resp(self, sender_id: str, ct_b64: str):
        """
        We initiated the handshake earlier. We now receive ciphertext and use
        our saved Kyber secret key to decap and derive the AES key.
        """
        secret_key = self.pending_kem.pop(sender_id, None)
        if secret_key is None:
            self._append_chat_line(
                f"[WARN] Received unexpected KEM_RESP from {sender_id}."
            )
            return

        try:
            ciphertext = base64.b64decode(ct_b64.encode("ascii"))
        except Exception:
            self._append_chat_line(
                f"[ERROR] Bad KEM_RESP from {sender_id}: invalid base64."
            )
            return

        try:
            shared_secret = decap_shared_secret(ciphertext, secret_key)
            aes_key = derive_aes_key(shared_secret)
            self.aes_keys[sender_id] = aes_key

            self._append_chat_line(
                f"[KEYX] Established AES key with {sender_id} (as initiator)."
            )
        except Exception as e:
            self._append_chat_line(
                f"[ERROR] KEM_RESP handling for {sender_id} failed: {e}"
            )

    def _handle_encrypted_msg(self, sender_id: str, encoded_cipher: str):
        aes_key = self.aes_keys.get(sender_id)
        if aes_key is None:
            self._append_chat_line(
                f"[WARN] Encrypted message from {sender_id}, "
                f"but no AES key is available."
            )
            return

        try:
            plaintext = aes_decrypt(aes_key, encoded_cipher)
            self._append_chat_line(f"{sender_id} → me: {plaintext}")
        except Exception as e:
            self._append_chat_line(
                f"[ERROR] Failed to decrypt message from {sender_id}: {e}"
            )

    def _append_chat_line(self, line: str):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, line + "\n")
        self.chat_area.see(tk.END)
        self.chat_area.config(state=tk.DISABLED)

    def on_close(self):
        try:
            if self.client_socket:
                self.client_socket.close()
        except Exception:
            pass
        self.master.destroy()


def main():
    root = tk.Tk()
    app = KyberAESChatClient(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
