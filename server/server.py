import os
import selectors
import socket
from client_session import ClientSession

def read_port():
    """
    Read the port from the port.info file
    :return: The port number. If the file doesn't exist, return the default port 1256
    """
    try:
        if os.path.exists("port.info"):
            with open("port.info", "r") as f:
                return int(f.read())
    except (ValueError, OSError) as e:
        print(f"Error reading port: {e}")
    return 1256  # default port

def handle_client(client_socket, sel):
    """
    Handle the client session
    :param client_socket: The client socket
    :param sel: The selector
    """
    try:
        with client_socket:
            client_session = ClientSession(client_socket)
            client_session.start()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sel.unregister(client_socket)
        client_socket.close()

def accept_wrapper(sock, sel):
    """
    Accept the client connection
    :param sock: The server socket
    :param sel: The selector
    """
    client_socket, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    client_socket.setblocking(True)
    sel.register(client_socket, selectors.EVENT_READ, lambda sock: handle_client(sock, sel))

def main():
    sel = selectors.DefaultSelector() # Threads can be used instead of selectors. But selectors are more efficient.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', read_port()))
        s.listen()
        s.setblocking(True)
        sel.register(s, selectors.EVENT_READ, lambda sock: accept_wrapper(sock, sel))
        print("Server started")

        while True:
            events = sel.select(timeout=None)
            for key, _ in events:
                if key.data is not None:
                    callback = key.data
                    callback(key.fileobj)

if __name__ == "__main__":
    main()