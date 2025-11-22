# pq_server_gui.py
import tkinter as tk
from tkinter import messagebox
import threading
import socketserver
from pyngrok import ngrok  # pip install pyngrok

# Global map: user_id -> socket
clients = {}


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    """
    Handles a single client connection in its own thread.
    Protocol:
      - First message from client: user_id (a single line/string)
      - Afterwards: 'recipient_id|payload'
    The server rewrites that to 'sender_id|payload' for the recipient.
    """

    def handle(self):
        client_socket = self.request
        user_id = None

        try:
            # First receive the user ID
            user_id = client_socket.recv(1024).decode("utf-8", errors="ignore").strip()
            if not user_id:
                client_socket.sendall(
                    "Invalid userID. Connection closed.".encode("utf-8")
                )
                client_socket.close()
                return

            if user_id in clients:
                client_socket.sendall(
                    "UserID already taken. Connection closed.".encode("utf-8")
                )
                client_socket.close()
                print(
                    f"[SERVER] Rejected connection from {self.client_address}: "
                    f"userID '{user_id}' already taken."
                )
                return

            # Register client
            clients[user_id] = client_socket
            client_socket.sendall("Connected successfully.".encode("utf-8"))
            print(f"[SERVER] '{user_id}' connected from {self.client_address}")

            # Main receive loop
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                message = data.decode("utf-8", errors="ignore")

                try:
                    recipient_id, payload = message.split("|", 1)
                except ValueError:
                    client_socket.sendall("Invalid message format.".encode("utf-8"))
                    continue

                route_message(recipient_id, payload, user_id)

        except Exception as e:
            print(f"[SERVER] Error handling client {self.client_address}: {e}")
        finally:
            if user_id and user_id in clients:
                del clients[user_id]
                print(f"[SERVER] '{user_id}' disconnected.")
            client_socket.close()


def route_message(recipient_id: str, payload: str, sender_id: str):
    """
    Forward payload from sender_id to recipient_id.
    Server never decrypts anything; it just rewrites the header.
    """
    recipient_socket = clients.get(recipient_id)
    if recipient_socket:
        try:
            full_message = f"{sender_id}|{payload}"
            recipient_socket.sendall(full_message.encode("utf-8"))
            print(
                f"[SERVER] Routed message from '{sender_id}' to '{recipient_id}': "
                f"{payload[:60]}..."
            )
        except Exception as e:
            print(f"[SERVER] Failed to send to '{recipient_id}': {e}")
            try:
                recipient_socket.close()
            except Exception:
                pass
            if recipient_id in clients:
                del clients[recipient_id]
    else:
        sender_socket = clients.get(sender_id)
        if sender_socket:
            try:
                notice = f"SERVER|Recipient '{recipient_id}' is not connected."
                sender_socket.sendall(notice.encode("utf-8"))
            except Exception:
                pass


class ServerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Kyber + AES Chat Server")

        # Fixed local port; Ngrok will expose this over the internet
        self.PORT = 5000

        self.server = None
        self.server_thread = None
        self.ngrok_tunnel = None

        # --- GUI widgets ---

        self.status_label = tk.Label(
            master, text="Server is NOT running.", fg="red", font=("Arial", 12)
        )
        self.status_label.pack(pady=5)

        self.start_button = tk.Button(
            master, text="Start Server", width=15, command=self.start_server
        )
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(
            master,
            text="Stop Server",
            width=15,
            command=self.stop_server,
            state=tk.DISABLED,
        )
        self.stop_button.pack(pady=5)

        self.ngrok_info_label = tk.Label(
            master, text="", fg="blue", font=("Arial", 10)
        )
        self.ngrok_info_label.pack(pady=10)

    def start_server(self):
        """Start the ThreadingTCPServer and open an Ngrok TCP tunnel."""
        try:
            # Open Ngrok TCP tunnel to self.PORT
            self.ngrok_tunnel = ngrok.connect(self.PORT, "tcp")
            public_url = self.ngrok_tunnel.public_url 

            parsed = public_url.replace("tcp://", "").split(":")
            ngrok_host = parsed[0]
            ngrok_port = parsed[1]

            self.ngrok_info_label.config(
                text=f"Ngrok address: {ngrok_host}:{ngrok_port}"
            )
            print(f"[SERVER] Ngrok address: {ngrok_host}:{ngrok_port}")

            # Start TCP server in background thread
            self.server = socketserver.ThreadingTCPServer(
                ("0.0.0.0", self.PORT), ThreadedTCPRequestHandler
            )
            self.server_thread = threading.Thread(
                target=self.server.serve_forever, daemon=True
            )
            self.server_thread.start()

            self.status_label.config(text="Server is RUNNING.", fg="green")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

        except Exception as e:
            messagebox.showerror("Error starting server", str(e))

    def stop_server(self):
        """Stop the TCP server and close the Ngrok tunnel."""
        # Stop TCP server
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
                print("[SERVER] Server stopped.")
            except Exception as e:
                print(f"[SERVER] Error stopping server: {e}")

        # Close Ngrok tunnel
        if self.ngrok_tunnel:
            try:
                ngrok.disconnect(self.ngrok_tunnel.public_url)
                print("[SERVER] Ngrok tunnel disconnected.")
            except Exception as e:
                print(f"[SERVER] Error disconnecting Ngrok: {e}")

        self.server = None
        self.server_thread = None
        self.ngrok_tunnel = None

        self.status_label.config(text="Server is NOT running.", fg="red")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.ngrok_info_label.config(text="")

    def on_close(self):
        self.stop_server()
        self.master.destroy()


def main():
    root = tk.Tk()
    gui = ServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", gui.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
