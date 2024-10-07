import socket
import threading

def handle_client(client_socket):
    with client_socket:
        ClientSession(client_socket).start()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', read_port()))
        s.listen()
        while True:
            client_socket, _ = s.accept()
            threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    main()