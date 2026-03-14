import socket


HOST = "127.0.0.1"
PORT = 4444
BUFFER_SIZE = 1024

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.connect((HOST, PORT))

        s.sendall(b"Hello world")

        data = s.recv(BUFFER_SIZE)

    print(f"Received: {data}!")

if __name__ == "__main__":
    main()