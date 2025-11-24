import argparse
import base64
import os
import socket
import sys
import time

import oqs
import psutil
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEM_ALG = "Kyber512"     
AES_KEY_LEN = 32          

CPU_POWER_WATTS = 4.0     



def derive_aes_key(shared_secret: bytes) -> bytes:
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
    Returns Base64( nonce || ciphertext || tag ).
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    combined = nonce + ct_with_tag
    return base64.b64encode(combined).decode("ascii")


def aes_decrypt(aes_key: bytes, encoded: str) -> str:
    """
    Decrypt Base64( nonce || ciphertext || tag ).
    """
    data = base64.b64decode(encoded.encode("ascii"))
    nonce = data[:12]
    ct_with_tag = data[12:]
    aesgcm = AESGCM(aes_key)
    pt_bytes = aesgcm.decrypt(nonce, ct_with_tag, None)
    return pt_bytes.decode("utf-8")


def generate_kem_keypair():
    """
    Generate KEM keypair and return (public_key, secret_key).
    """
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk


def decap_shared_secret(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Recover shared secret from ciphertext + secret key.
    Handles different oqs versions.
    """
    try:
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            kem.import_secret_key(secret_key)
            ss = kem.decap_secret(ciphertext)
    except AttributeError:
        with oqs.KeyEncapsulation(KEM_ALG, secret_key) as kem:
            ss = kem.decap_secret(ciphertext)
    return ss



class BenchClient:
    def __init__(self, args):
        self.server_host = args.server_host
        self.server_port = args.server_port
        self.user_id = args.user_id
        self.peer_id = args.peer_id
        self.role = args.role
        self.num_messages = args.num_messages
        self.message_size = args.message_size

        self.sock = None
        self.aes_key = None

        # Metrics
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.plain_bytes_sent = 0
        self.latencies = []
        self.key_sizes = {}
        self.per_message_sizes = {}

    # ---- basic I/O ----

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))

        # First thing: send user_id 
        self.sock.sendall(self.user_id.encode("utf-8"))
        self.bytes_sent += len(self.user_id.encode("utf-8"))

        ack = self.sock.recv(1024)
        self.bytes_recv += len(ack)
        print("[INFO] Server says:", ack.decode("utf-8", errors="ignore").strip())

    def send_message(self, recipient_id: str, payload: str):
        """
        Send a single protocol message: 'recipient_id|payload'
        """
        msg = f"{recipient_id}|{payload}"
        data = msg.encode("utf-8")
        self.sock.sendall(data)
        self.bytes_sent += len(data)

    def recv_message(self) -> str:
        """
        Receive a full message (assumes one per recv, like your GUI client).
        """
        data = self.sock.recv(65535)
        if not data:
            raise ConnectionError("Server closed connection")
        self.bytes_recv += len(data)
        return data.decode("utf-8", errors="ignore")

    # ---- handshake ----

    def run_handshake_sender(self):
        """
        Sender initiates the Kyber KEM handshake.
        """
        print("[HANDSHAKE] Sender: generating keypair...")
        pk, sk = generate_kem_keypair()

        # Record key sizes for storage overhead
        self.key_sizes["pk_bytes"] = len(pk)
        self.key_sizes["sk_bytes"] = len(sk)

        pk_b64 = base64.b64encode(pk).decode("ascii")
        self.send_message(self.peer_id, f"KEM_INIT:{pk_b64}")

        print("[HANDSHAKE] Sender: waiting for KEM_RESP...")
        while True:
            msg = self.recv_message()
            sender_id, payload = msg.split("|", 1)
            if not payload.startswith("KEM_RESP:"):
                print("[HANDSHAKE] Sender: ignoring non-KEM_RESP:", msg)
                continue

            ct_b64 = payload[len("KEM_RESP:"):]
            ct = base64.b64decode(ct_b64.encode("ascii"))
            self.key_sizes["kem_ciphertext_bytes"] = len(ct)

            ss = decap_shared_secret(ct, sk)
            self.aes_key = derive_aes_key(ss)
            print("[HANDSHAKE] Sender: AES key established.")
            break

        # AES key size
        self.key_sizes["aes_key_bytes"] = len(self.aes_key)

    def run_handshake_receiver(self):
        """
        Receiver waits for KEM_INIT, responds with KEM_RESP.
        """
        print("[HANDSHAKE] Receiver: waiting for KEM_INIT...")
        while True:
            msg = self.recv_message()
            sender_id, payload = msg.split("|", 1)
            if not payload.startswith("KEM_INIT:"):
                print("[HANDSHAKE] Receiver: ignoring non-KEM_INIT:", msg)
                continue

            pk_b64 = payload[len("KEM_INIT:"):]
            pk = base64.b64decode(pk_b64.encode("ascii"))
            self.key_sizes["pk_bytes"] = len(pk)

            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                ct, ss = kem.encap_secret(pk)

            self.key_sizes["kem_ciphertext_bytes"] = len(ct)

            self.aes_key = derive_aes_key(ss)
            self.key_sizes["aes_key_bytes"] = len(self.aes_key)

            ct_b64 = base64.b64encode(ct).decode("ascii")
            self.send_message(sender_id, f"KEM_RESP:{ct_b64}")
            print("[HANDSHAKE] Receiver: AES key established.")
            break

    # ---- benchmark roles ----

    def run_sender_benchmark(self):
        """
        Sender sends N messages and waits for an ACK for each.
        Measures:
          - Round-trip latency
          - Throughput
          - CPU/RAM usage
          - Energy estimate
          - Overheads
        """
        if self.aes_key is None:
            raise RuntimeError("AES key not established")

        proc = psutil.Process(os.getpid())
        cpu_times_start = proc.cpu_times()
        rss_start = proc.memory_info().rss

        plain_example_len = None
        cipher_bin_example_len = None
        cipher_b64_example_len = None

        print(f"[BENCH] Sending {self.num_messages} messages "
              f"of {self.message_size} bytes each...")

        start_wall = time.perf_counter()

        for i in range(self.num_messages):
            # Create plaintext of fixed size
            base_text = f"MSG {i}".encode("utf-8")
            if len(base_text) > self.message_size:
                pt_bytes = base_text[:self.message_size]
            else:
                pt_bytes = base_text.ljust(self.message_size, b"X")
            plaintext = pt_bytes.decode("utf-8", errors="ignore")

            self.plain_bytes_sent += len(pt_bytes)

            # First message: record per-message sizes for storage overhead
            if i == 0:
                tmp_cipher_b64 = aes_encrypt(self.aes_key, plaintext)
                cipher_bin = base64.b64decode(tmp_cipher_b64.encode("ascii"))
                plain_example_len = len(pt_bytes)
                cipher_bin_example_len = len(cipher_bin)
                cipher_b64_example_len = len(tmp_cipher_b64.encode("ascii"))

            t0 = time.perf_counter()
            cipher_b64 = aes_encrypt(self.aes_key, plaintext)
            payload = f"MSG:{cipher_b64}"
            self.send_message(self.peer_id, payload)

            # Wait for ACK
            ack_msg = self.recv_message()
            t1 = time.perf_counter()
            self.latencies.append(t1 - t0)

            try:
                sender_id, ack_payload = ack_msg.split("|", 1)
                if ack_payload.startswith("MSG:"):
                    ack_cipher = ack_payload[len("MSG:"):]
                    _ = aes_decrypt(self.aes_key, ack_cipher)
            except Exception:
                pass

            if (i + 1) % max(1, self.num_messages // 10) == 0:
                print(f"[BENCH] Progress: {i + 1}/{self.num_messages} messages")

        end_wall = time.perf_counter()
        cpu_times_end = proc.cpu_times()
        rss_end = proc.memory_info().rss

        # CPU & RAM stats
        cpu_user = cpu_times_end.user - cpu_times_start.user
        cpu_sys = cpu_times_end.system - cpu_times_start.system
        cpu_time = cpu_user + cpu_sys
        wall_time = end_wall - start_wall
        cpu_count = psutil.cpu_count(logical=True) or 1
        approx_cpu_percent = 100.0 * cpu_time / (wall_time * cpu_count)

        rss_max = max(rss_start, rss_end)
        energy_joules = CPU_POWER_WATTS * cpu_time  

        # Throughput
        throughput_bps = self.plain_bytes_sent / wall_time
        throughput_kbps = throughput_bps / 1024.0

        # Latency stats
        if self.latencies:
            lat_ms = [x * 1000.0 for x in self.latencies]
            avg_lat = sum(lat_ms) / len(lat_ms)
            min_lat = min(lat_ms)
            max_lat = max(lat_ms)
        else:
            avg_lat = min_lat = max_lat = 0.0

        self.per_message_sizes = {
            "plain_example_len": plain_example_len,
            "cipher_bin_example_len": cipher_bin_example_len,
            "cipher_b64_example_len": cipher_b64_example_len,
        }

        # Print summary
        print("\n========== BENCHMARK RESULTS ==========")
        print(f"Role:               sender")
        print(f"Messages:           {self.num_messages}")
        print(f"Payload size:       {self.message_size} bytes")
        print(f"Total payload sent: {self.plain_bytes_sent} bytes")
        print(f"Wall time:          {wall_time:.4f} s")
        print()
        print(f"Latency (RTT):      avg={avg_lat:.3f} ms, "
              f"min={min_lat:.3f} ms, max={max_lat:.3f} ms")
        print(f"Throughput:         {throughput_kbps:.2f} KiB/s")
        print()
        print(f"CPU time (user+sys): {cpu_time:.4f} s")
        print(f"Approx CPU usage:    {approx_cpu_percent:.2f} %")
        print(f"RSS memory (approx): {rss_max / (1024*1024):.2f} MiB")
        print(f"Energy (approx):     {energy_joules:.4f} J "
              f"(assuming {CPU_POWER_WATTS} W CPU)")
        print()
        print(f"Bytes sent (total):  {self.bytes_sent}")
        print(f"Bytes recv (total):  {self.bytes_recv}")
        print(f"Comm overhead:       {self.bytes_sent - self.plain_bytes_sent} bytes "
              f"over plaintext sent")
        if self.plain_bytes_sent > 0:
            overhead_ratio = (self.bytes_sent - self.plain_bytes_sent) / self.plain_bytes_sent
            print(f"Overhead ratio:      {overhead_ratio * 100:.2f} %")
        print()
        print("Key / storage sizes:")
        for k, v in self.key_sizes.items():
            print(f"  {k}: {v} bytes")
        if plain_example_len is not None:
            print("Per-message sizes (1st message):")
            print(f"  plaintext:         {plain_example_len} bytes")
            print(f"  AES-GCM binary:    {cipher_bin_example_len} bytes "
                  f"(nonce + ct + tag)")
            print(f"  Base64 stored:     {cipher_b64_example_len} bytes")
        print("=======================================\n")

    def run_receiver_loop(self):
        """
        Receiver decrypts incoming messages and sends ACKs.
        Runs indefinitely until Ctrl+C.
        """
        if self.aes_key is None:
            raise RuntimeError("AES key not established")

        print("[BENCH] Receiver ready: waiting for encrypted messages...")

        while True:
            msg = self.recv_message()
            sender_id, payload = msg.split("|", 1)
            if not payload.startswith("MSG:"):
                print("[BENCH] Receiver: ignoring non-MSG:", msg)
                continue

            cipher_b64 = payload[len("MSG:"):]
            try:
                _plaintext = aes_decrypt(self.aes_key, cipher_b64)
            except Exception as e:
                print("[BENCH] Receiver: decryption error:", e)
                continue

            # Send ACK
            ack_plain = "ACK"
            ack_cipher = aes_encrypt(self.aes_key, ack_plain)
            self.send_message(sender_id, f"MSG:{ack_cipher}")


def parse_args():
    p = argparse.ArgumentParser(description="Kyber+AES chat benchmark client")
    p.add_argument("--server-host", required=True, help="Ngrok host")
    p.add_argument("--server-port", type=int, required=True, help="Ngrok port")
    p.add_argument("--user-id", required=True, help="This client's user ID")
    p.add_argument("--peer-id", required=True, help="Other side's user ID")
    p.add_argument("--role", choices=["sender", "receiver"], required=True)
    p.add_argument("--num-messages", type=int, default=100,
                   help="Number of messages to send (sender only)")
    p.add_argument("--message-size", type=int, default=256,
                   help="Payload size per message in bytes (sender only)")
    return p.parse_args()


def main():
    args = parse_args()
    client = BenchClient(args)

    try:
        client.connect()
        if args.role == "sender":
            client.run_handshake_sender()
            client.run_sender_benchmark()
        else:
            client.run_handshake_receiver()
            client.run_receiver_loop()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
    except Exception as e:
        print("[ERROR]", e)
    finally:
        try:
            if client.sock:
                client.sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
