import socket


HOST = "127.0.0.1"
PORT = 4444
BUFFER_SIZE = 1024

def receive_message(server_socket):

    try:
        data = server_socket.recv(BUFFER_SIZE)
        if not data:
            return None;

        data_str = data.decode("utf-8")

        return data_str

    except Exception as e:
        return f"Error: {str(e)}"

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.connect((HOST, PORT))

        while True:
            message = input('client> ').strip()

            if message == "exit":
                break

            s.sendall(message.encode("utf-8"))

            response = receive_message(s)

            print(f"Server response: {response}")

if __name__ == "__main__":
    main()