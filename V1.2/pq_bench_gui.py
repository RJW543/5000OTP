import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox, scrolledtext

import socket
import threading
import base64
import os
import time

import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import psutil
except ImportError:
    psutil = None

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
    AES-GCM encrypt, returning Base64( nonce || ciphertext || tag ).
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    combined = nonce + ct_with_tag
    return base64.b64encode(combined).decode("ascii")


def aes_decrypt(aes_key: bytes, encoded: str) -> str:
    data = base64.b64decode(encoded.encode("ascii"))
    nonce = data[:12]
    ct_with_tag = data[12:]
    aesgcm = AESGCM(aes_key)
    pt_bytes = aesgcm.decrypt(nonce, ct_with_tag, None)
    return pt_bytes.decode("utf-8")


def generate_kem_keypair():
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk


def decap_shared_secret(ciphertext: bytes, secret_key: bytes) -> bytes:
    try:
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            kem.import_secret_key(secret_key)
            ss = kem.decap_secret(ciphertext)
    except AttributeError:
        with oqs.KeyEncapsulation(KEM_ALG, secret_key) as kem:
            ss = kem.decap_secret(ciphertext)
    return ss

class BenchGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Kyber + AES Benchmark Client")

        self.sock = None
        self.server_host = None
        self.server_port = None
        self.user_id = None
        self.peer_id = None
        self.role = tk.StringVar(value="sender") 

        self.aes_key = None
        self.key_sizes = {}

        self.bytes_sent = 0
        self.bytes_recv = 0
        self.plain_bytes_sent = 0
        self.latencies = []
        self.per_message_sizes = {}
        self.num_messages = tk.IntVar(value=100)
        self.message_size = tk.IntVar(value=256)

        self.key_status_var = tk.StringVar(value="No AES key established.")
        self.bench_running = False

        self._build_gui()

    def _build_gui(self):
        root = self.master

        main = ttk.Frame(root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        server_frame = ttk.LabelFrame(main, text="Server (Ngrok) Address")
        server_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
        server_frame.columnconfigure(1, weight=1)

        ttk.Label(server_frame, text="Host:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.host_entry = ttk.Entry(server_frame, width=25)
        self.host_entry.insert(0, "0.tcp.ngrok.io")
        self.host_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(server_frame, text="Port:").grid(row=0, column=2, padx=5, pady=5, sticky="e")
        self.port_entry = ttk.Entry(server_frame, width=8)
        self.port_entry.insert(0, "12345")
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)

        self.set_server_button = ttk.Button(
            server_frame, text="Set Server", command=self.set_server
        )
        self.set_server_button.grid(row=0, column=4, padx=10, pady=5)

        id_frame = ttk.LabelFrame(main, text="Identity & Role")
        id_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        id_frame.columnconfigure(1, weight=1)

        ttk.Label(id_frame, text="User ID:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.user_entry = ttk.Entry(id_frame, width=20)
        self.user_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(id_frame, text="Peer ID:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.peer_entry = ttk.Entry(id_frame, width=20)
        self.peer_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        role_frame = ttk.Frame(id_frame)
        role_frame.grid(row=0, column=2, rowspan=2, padx=10, pady=5)
        ttk.Label(role_frame, text="Role:").grid(row=0, column=0, padx=5, pady=2)
        ttk.Radiobutton(role_frame, text="Sender", variable=self.role, value="sender").grid(
            row=1, column=0, sticky="w"
        )
        ttk.Radiobutton(role_frame, text="Receiver", variable=self.role, value="receiver").grid(
            row=2, column=0, sticky="w"
        )

        self.connect_button = ttk.Button(id_frame, text="Connect", command=self.connect)
        self.connect_button.grid(row=0, column=3, rowspan=2, padx=10, pady=5)

        self.conn_status = ttk.Label(id_frame, text="Not connected.", foreground="red")
        self.conn_status.grid(row=2, column=0, columnspan=4, sticky="w", padx=5)

        param_frame = ttk.LabelFrame(main, text="Benchmark Parameters (Sender)")
        param_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)
        param_frame.columnconfigure(1, weight=1)

        ttk.Label(param_frame, text="Messages:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.msgs_entry = ttk.Entry(param_frame, textvariable=self.num_messages, width=10)
        self.msgs_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(param_frame, text="Payload size (bytes):").grid(
            row=0, column=2, padx=5, pady=5, sticky="e"
        )
        self.size_entry = ttk.Entry(param_frame, textvariable=self.message_size, width=10)
        self.size_entry.grid(row=0, column=3, padx=5, pady=5, sticky="w")

        action_frame = ttk.LabelFrame(main, text="Actions")
        action_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5)

        self.handshake_button = ttk.Button(
            action_frame, text="Run Key Exchange", command=self.start_handshake_thread
        )
        self.handshake_button.grid(row=0, column=0, padx=5, pady=5)

        self.run_button = ttk.Button(
            action_frame, text="Run Benchmark", command=self.start_benchmark_thread
        )
        self.run_button.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(action_frame, text="Key status:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.key_status_label = ttk.Label(
            action_frame, textvariable=self.key_status_var, foreground="red"
        )
        self.key_status_label.grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky="w")

        log_frame = ttk.LabelFrame(main, text="Log & Results")
        log_frame.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=5)
        main.rowconfigure(4, weight=1)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(
            log_frame, width=80, height=25, state=tk.DISABLED
        )
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

    def log(self, text: str):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def set_key_status(self, msg: str, colour: str):
        self.key_status_var.set(msg)
        self.key_status_label.config(foreground=colour)

    def set_server(self):
        host = self.host_entry.get().strip()
        port = self.port_entry.get().strip()
        if not host or not port:
            messagebox.showwarning("Warning", "Please set both host and port.")
            return
        if not port.isdigit():
            messagebox.showwarning("Warning", "Port must be numeric.")
            return
        self.server_host = host
        self.server_port = int(port)
        messagebox.showinfo("Server set", f"{host}:{port} configured.")

    def connect(self):
        if not self.server_host or not self.server_port:
            messagebox.showwarning("Warning", "Set server host/port first.")
            return

        user_id = self.user_entry.get().strip()
        peer_id = self.peer_entry.get().strip()
        if not user_id or not peer_id:
            messagebox.showwarning("Warning", "Specify both User ID and Peer ID.")
            return
        if user_id == peer_id:
            messagebox.showwarning("Warning", "User ID and Peer ID must differ.")
            return

        self.user_id = user_id
        self.peer_id = peer_id

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_host, self.server_port))

            data = self.user_id.encode("utf-8")
            self.sock.sendall(data)
            self.bytes_sent += len(data)

            ack = self.sock.recv(1024)
            self.bytes_recv += len(ack)

            self.log(f"[INFO] Connected. Server: {ack.decode('utf-8', errors='ignore').strip()}")
            self.conn_status.config(text="Connected.", foreground="green")

            self.aes_key = None
            self.key_sizes = {}
            self.bytes_sent = len(data) + len(ack)
            self.bytes_recv = 0  
            self.plain_bytes_sent = 0
            self.latencies = []
            self.per_message_sizes = {}

            self.set_key_status("No AES key established.", "red")

        except Exception as e:
            messagebox.showerror("Connection error", str(e))
            self.conn_status.config(text="Not connected.", foreground="red")
            self.sock = None


    def send_proto(self, recipient_id: str, payload: str):
        msg = f"{recipient_id}|{payload}"
        data = msg.encode("utf-8")
        self.sock.sendall(data)
        self.bytes_sent += len(data)

    def recv_proto(self) -> str:
        data = self.sock.recv(65535)
        if not data:
            raise ConnectionError("Server closed connection")
        self.bytes_recv += len(data)
        return data.decode("utf-8", errors="ignore")

    def start_handshake_thread(self):
        if not self.sock:
            messagebox.showwarning("Warning", "Connect first.")
            return
        t = threading.Thread(target=self.handshake_thread, daemon=True)
        t.start()

    def handshake_thread(self):
        role = self.role.get()
        try:
            if role == "sender":
                self.log("[HANDSHAKE] Acting as Sender (initiator).")
                self._handshake_sender()
            else:
                self.log("[HANDSHAKE] Acting as Receiver (responder).")
                self._handshake_receiver()

            self.set_key_status("AES key established.", "green")
            self.log("[HANDSHAKE] AES key successfully established.")

        except Exception as e:
            self.log(f"[HANDSHAKE ERROR] {e}")
            self.set_key_status("Handshake failed.", "red")

    def _handshake_sender(self):
        pk, sk = generate_kem_keypair()
        self.key_sizes["pk_bytes"] = len(pk)
        self.key_sizes["sk_bytes"] = len(sk)

        pk_b64 = base64.b64encode(pk).decode("ascii")
        self.send_proto(self.peer_id, f"KEM_INIT:{pk_b64}")
        self.log("[HANDSHAKE] Sender: KEM_INIT sent, waiting for KEM_RESP...")

        while True:
            msg = self.recv_proto()
            if "|" not in msg:
                self.log(f"[HANDSHAKE] Ignoring non-protocol msg: {msg}")
                continue
            sender_id, payload = msg.split("|", 1)
            if not payload.startswith("KEM_RESP:"):
                self.log(f"[HANDSHAKE] Ignoring non-KEM_RESP: {msg}")
                continue

            ct_b64 = payload[len("KEM_RESP:"):]
            ct = base64.b64decode(ct_b64.encode("ascii"))
            self.key_sizes["kem_ciphertext_bytes"] = len(ct)

            ss = decap_shared_secret(ct, sk)
            self.aes_key = derive_aes_key(ss)
            self.key_sizes["aes_key_bytes"] = len(self.aes_key)
            break

    def _handshake_receiver(self):
        self.log("[HANDSHAKE] Receiver: waiting for KEM_INIT...")
        while True:
            msg = self.recv_proto()
            if "|" not in msg:
                self.log(f"[HANDSHAKE] Ignoring non-protocol msg: {msg}")
                continue
            sender_id, payload = msg.split("|", 1)
            if not payload.startswith("KEM_INIT:"):
                self.log(f"[HANDSHAKE] Ignoring non-KEM_INIT: {msg}")
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
            self.send_proto(sender_id, f"KEM_RESP:{ct_b64}")
            break

    def start_benchmark_thread(self):
        if not self.sock:
            messagebox.showwarning("Warning", "Connect first.")
            return
        if self.aes_key is None:
            messagebox.showwarning("Warning", "Run key exchange first.")
            return

        try:
            n = int(self.msgs_entry.get())
            sz = int(self.size_entry.get())
        except ValueError:
            messagebox.showwarning("Warning", "Messages and payload size must be integers.")
            return

        self.num_messages.set(n)
        self.message_size.set(sz)

        if self.role.get() == "sender":
            t = threading.Thread(target=self.sender_bench_thread, daemon=True)
        else:
            t = threading.Thread(target=self.receiver_bench_thread, daemon=True)
        t.start()

    def sender_bench_thread(self):
        if self.bench_running:
            self.log("[BENCH] Already running.")
            return
        self.bench_running = True

        n = self.num_messages.get()
        size = self.message_size.get()
        self.log(f"[BENCH] Sender: {n} messages, payload size {size} bytes.")

        proc = psutil.Process(os.getpid()) if psutil else None

        if proc:
            cpu_start = proc.cpu_times()
            rss_start = proc.memory_info().rss
        else:
            cpu_start = rss_start = None

        self.bytes_sent = 0 
        self.bytes_recv = 0
        self.plain_bytes_sent = 0
        self.latencies = []
        self.per_message_sizes = {}
        plain_example_len = None
        cipher_bin_example_len = None
        cipher_b64_example_len = None

        start_wall = time.perf_counter()

        try:
            for i in range(n):
                base = f"MSG {i}".encode("utf-8")
                if len(base) > size:
                    pt_bytes = base[:size]
                else:
                    pt_bytes = base.ljust(size, b"X")
                plaintext = pt_bytes.decode("utf-8", errors="ignore")
                self.plain_bytes_sent += len(pt_bytes)

                if i == 0:
                    tmp_cipher_b64 = aes_encrypt(self.aes_key, plaintext)
                    cipher_bin = base64.b64decode(tmp_cipher_b64.encode("ascii"))
                    plain_example_len = len(pt_bytes)
                    cipher_bin_example_len = len(cipher_bin)
                    cipher_b64_example_len = len(tmp_cipher_b64.encode("ascii"))

                t0 = time.perf_counter()
                cipher_b64 = aes_encrypt(self.aes_key, plaintext)
                self.send_proto(self.peer_id, f"MSG:{cipher_b64}")

                ack_msg = self.recv_proto()
                t1 = time.perf_counter()
                self.latencies.append(t1 - t0)

                try:
                    sender_id, payload = ack_msg.split("|", 1)
                    if payload.startswith("MSG:"):
                        ack_ct = payload[len("MSG:"):]
                        _ = aes_decrypt(self.aes_key, ack_ct)
                except Exception:
                    pass

                if (i + 1) % max(1, n // 10) == 0:
                    self.log(f"[BENCH] Progress: {i + 1}/{n} messages")

        except Exception as e:
            self.log(f"[BENCH ERROR] Sender: {e}")
        finally:
            end_wall = time.perf_counter()
            if proc:
                cpu_end = proc.cpu_times()
                rss_end = proc.memory_info().rss
            else:
                cpu_end = rss_end = None

            self.per_message_sizes = {
                "plain_example_len": plain_example_len,
                "cipher_bin_example_len": cipher_bin_example_len,
                "cipher_b64_example_len": cipher_b64_example_len,
            }

            self._report_sender_results(start_wall, end_wall,
                                        cpu_start, cpu_end,
                                        rss_start, rss_end)
            self.bench_running = False

    def _report_sender_results(self, start_wall, end_wall,
                               cpu_start, cpu_end,
                               rss_start, rss_end):
        wall_time = end_wall - start_wall
        n = self.num_messages.get()
        size = self.message_size.get()

        if self.latencies:
            lat_ms = [x * 1000.0 for x in self.latencies]
            avg_lat = sum(lat_ms) / len(lat_ms)
            min_lat = min(lat_ms)
            max_lat = max(lat_ms)
        else:
            avg_lat = min_lat = max_lat = 0.0

        throughput_bps = self.plain_bytes_sent / wall_time if wall_time > 0 else 0.0
        throughput_kib = throughput_bps / 1024.0

        if psutil and cpu_start and cpu_end:
            cpu_user = cpu_end.user - cpu_start.user
            cpu_sys = cpu_end.system - cpu_start.system
            cpu_time = cpu_user + cpu_sys
            cpu_count = psutil.cpu_count(logical=True) or 1
            approx_cpu_percent = 100.0 * cpu_time / (wall_time * cpu_count) if wall_time > 0 else 0.0
            rss_max = max(rss_start, rss_end)
            energy_joules = CPU_POWER_WATTS * cpu_time
        else:
            cpu_time = approx_cpu_percent = rss_max = energy_joules = None

        comm_overhead = self.bytes_sent - self.plain_bytes_sent
        overhead_ratio = (
            (comm_overhead / self.plain_bytes_sent) * 100.0
            if self.plain_bytes_sent > 0 else 0.0
        )

        s = []
        s.append("========== BENCHMARK RESULTS (SENDER) ==========")
        s.append(f"Messages:           {n}")
        s.append(f"Payload size:       {size} bytes")
        s.append(f"Total payload sent: {self.plain_bytes_sent} bytes")
        s.append(f"Wall time:          {wall_time:.4f} s")
        s.append("")
        s.append(f"Latency (RTT):      avg={avg_lat:.3f} ms, "
                 f"min={min_lat:.3f} ms, max={max_lat:.3f} ms")
        s.append(f"Throughput:         {throughput_kib:.2f} KiB/s")
        s.append("")
        if cpu_time is not None:
            s.append(f"CPU time (user+sys): {cpu_time:.4f} s")
            s.append(f"Approx CPU usage:    {approx_cpu_percent:.2f} %")
            s.append(f"RSS memory (approx): {rss_max / (1024*1024):.2f} MiB")
            s.append(f"Energy (approx):     {energy_joules:.4f} J "
                     f"(assuming {CPU_POWER_WATTS} W CPU)")
        else:
            s.append("CPU/RAM/Energy:     psutil not available.")
        s.append("")
        s.append(f"Bytes sent (total):  {self.bytes_sent}")
        s.append(f"Bytes recv (total):  {self.bytes_recv}")
        s.append(f"Comm overhead:       {comm_overhead} bytes over plaintext")
        s.append(f"Overhead ratio:      {overhead_ratio:.2f} %")
        s.append("")
        if self.key_sizes:
            s.append("Key / storage sizes:")
            for k, v in self.key_sizes.items():
                s.append(f"  {k}: {v} bytes")
        if self.per_message_sizes.get("plain_example_len") is not None:
            s.append("Per-message sizes (1st message):")
            s.append(f"  plaintext:         {self.per_message_sizes['plain_example_len']} bytes")
            s.append(f"  AES-GCM binary:    {self.per_message_sizes['cipher_bin_example_len']} bytes")
            s.append(f"  Base64 stored:     {self.per_message_sizes['cipher_b64_example_len']} bytes")
        s.append("================================================")

        self.log("\n".join(s))

    def receiver_bench_thread(self):
        if self.bench_running:
            self.log("[BENCH] Already running.")
            return
        self.bench_running = True

        n = self.num_messages.get()
        self.log(f"[BENCH] Receiver: waiting for {n} encrypted messages...")

        proc = psutil.Process(os.getpid()) if psutil else None
        if proc:
            cpu_start = proc.cpu_times()
            rss_start = proc.memory_info().rss
        else:
            cpu_start = rss_start = None

        self.bytes_sent = 0
        self.bytes_recv = 0

        handled = 0
        plain_example_len = None
        cipher_bin_example_len = None
        cipher_b64_example_len = None

        start_wall = time.perf_counter()

        try:
            while handled < n:
                msg = self.recv_proto()
                if "|" not in msg:
                    self.log(f"[BENCH] Receiver: ignoring malformed msg: {msg}")
                    continue
                sender_id, payload = msg.split("|", 1)
                if not payload.startswith("MSG:"):
                    self.log(f"[BENCH] Receiver: ignoring non-MSG: {msg}")
                    continue

                cipher_b64 = payload[len("MSG:"):]
                # sample sizes
                if handled == 0:
                    cipher_bin = base64.b64decode(cipher_b64.encode("ascii"))
                    cipher_bin_example_len = len(cipher_bin)
                    cipher_b64_example_len = len(cipher_b64.encode("ascii"))

                try:
                    plaintext = aes_decrypt(self.aes_key, cipher_b64)
                except Exception as e:
                    self.log(f"[BENCH] Receiver: decryption error: {e}")
                    continue

                if handled == 0:
                    plain_example_len = len(plaintext.encode("utf-8", errors="ignore"))

                ack_plain = "ACK"
                ack_ct = aes_encrypt(self.aes_key, ack_plain)
                self.send_proto(sender_id, f"MSG:{ack_ct}")

                handled += 1
                if handled % max(1, n // 10) == 0:
                    self.log(f"[BENCH] Receiver progress: {handled}/{n}")

        except Exception as e:
            self.log(f"[BENCH ERROR] Receiver: {e}")
        finally:
            end_wall = time.perf_counter()
            if proc:
                cpu_end = proc.cpu_times()
                rss_end = proc.memory_info().rss
            else:
                cpu_end = rss_end = None

            self.per_message_sizes = {
                "plain_example_len": plain_example_len,
                "cipher_bin_example_len": cipher_bin_example_len,
                "cipher_b64_example_len": cipher_b64_example_len,
            }

            self._report_receiver_results(
                start_wall, end_wall,
                cpu_start, cpu_end,
                rss_start, rss_end,
                handled
            )
            self.bench_running = False

    def _report_receiver_results(self, start_wall, end_wall,
                                 cpu_start, cpu_end,
                                 rss_start, rss_end,
                                 handled):
        wall_time = end_wall - start_wall
        n = handled

        if psutil and cpu_start and cpu_end:
            cpu_user = cpu_end.user - cpu_start.user
            cpu_sys = cpu_end.system - cpu_start.system
            cpu_time = cpu_user + cpu_sys
            cpu_count = psutil.cpu_count(logical=True) or 1
            approx_cpu_percent = 100.0 * cpu_time / (wall_time * cpu_count) if wall_time > 0 else 0.0
            rss_max = max(rss_start, rss_end)
            energy_joules = CPU_POWER_WATTS * cpu_time
        else:
            cpu_time = approx_cpu_percent = rss_max = energy_joules = None

        s = []
        s.append("========== BENCHMARK RESULTS (RECEIVER) =========")
        s.append(f"Messages handled:    {n}")
        s.append(f"Wall time:           {wall_time:.4f} s")
        s.append("")
        if cpu_time is not None:
            s.append(f"CPU time (user+sys): {cpu_time:.4f} s")
            s.append(f"Approx CPU usage:    {approx_cpu_percent:.2f} %")
            s.append(f"RSS memory (approx): {rss_max / (1024*1024):.2f} MiB")
            s.append(f"Energy (approx):     {energy_joules:.4f} J "
                     f"(assuming {CPU_POWER_WATTS} W CPU)")
        else:
            s.append("CPU/RAM/Energy:      psutil not available.")
        s.append("")
        s.append(f"Bytes sent (total):  {self.bytes_sent}")
        s.append(f"Bytes recv (total):  {self.bytes_recv}")
        s.append("")
        if self.per_message_sizes.get("plain_example_len") is not None:
            s.append("Per-message sizes (1st message):")
            s.append(f"  plaintext:         {self.per_message_sizes['plain_example_len']} bytes")
            s.append(f"  AES-GCM binary:    {self.per_message_sizes['cipher_bin_example_len']} bytes")
            s.append(f"  Base64 stored:     {self.per_message_sizes['cipher_b64_example_len']} bytes")
        s.append("=================================================")

        self.log("\n".join(s))

    def on_close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.master.destroy()


def main():
    root = tk.Tk()
    app = BenchGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
