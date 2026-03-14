import socket
import threading

HOST = "127.0.0.1"  # loopback
PORT = 4444
BUFFER_SIZE = 1024

def handle_client(client_socket):
    with client_socket:
        while True:
            try:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break

                response_data = data
                client_socket.sendall(response_data)

            except Exception as e:
                client_socket.sendall(f"Error: {str(e)}".encode("utf-8"))
                break

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.bind((HOST, PORT))

        s.listen()

        while True:
            client_socket, addr = s.accept()
            print(f"[SERVER] Connection from {addr}")

            threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    main()