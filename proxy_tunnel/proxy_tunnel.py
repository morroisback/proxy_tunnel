import base64
import logging
import select
import socket

from contextlib import contextmanager
from dataclasses import dataclass
from threading import Thread
from typing import Iterator


logging.basicConfig(level=logging.DEBUG)


@contextmanager
def socket_timeout(sock: socket.socket, timeout: float = 0.5) -> Iterator[None]:
    sock.settimeout(timeout)
    try:
        yield
    except socket.timeout:
        pass
    finally:
        sock.settimeout(None)


@dataclass
class Proxy:
    host: str
    port: str
    username: str = ""
    password: str = ""
    refresh_url: str = ""

    def __repr__(self) -> str:
        if self.username and self.password:
            return f"ProxyData(host={self.host}, port={self.port}, username={self.username}, password=****)"
        else:
            return f"ProxyData(host={self.host}, port={self.port})"

    def __str__(self) -> str:
        if self.username and self.password:
            return f"{self.username}:{self.password}@{self.host}:{self.port}"
        else:
            return f"{self.host}:{self.port}"


class Connection:
    def __init__(
        self, thread_id: int, local_socket: socket.socket, remote_socket: socket.socket, logger: logging.Logger
    ) -> None:
        self.thread_id = thread_id
        self.local_socket = local_socket
        self.remote_socket = remote_socket
        self.logger = logger
        self.thread: Thread | None = None
        self.is_auth = False

    @staticmethod
    def recv_data(sock: socket.socket, chunk_size: int = 4096, timeout: float = 0.5) -> bytes:
        chunks = []
        with socket_timeout(sock, timeout):
            while True:
                data = sock.recv(chunk_size)
                if not data:
                    break
                chunks.append(data)

        return b"".join(chunks)

    @staticmethod
    def send_data(sock: socket.socket, data: bytes) -> int:
        total_send = 0
        data_size = len(data)
        while total_send < data_size:
            select.select([], [sock], [])
            send = sock.send(data[total_send:])
            if not send:
                break
            total_send += send

        return total_send

    @staticmethod
    def add_auth_header(request: bytes, proxy_authorization: str) -> bytes:
        headers, body = request.split(b"\r\n\r\n", 1)
        headers_list = headers.split(b"\r\n")

        modified_headers = []
        auth_header = b"Proxy-Authorization: " + proxy_authorization.encode()

        inserted = False
        for header in headers_list:
            if header.startswith(b"Proxy-Authorization:"):
                modified_headers.append(auth_header)
                inserted = True
            else:
                modified_headers.append(header)

        if not inserted:
            modified_headers.append(auth_header)

        request = b"\r\n".join(modified_headers) + b"\r\n\r\n" + body

        return request

    def close_connection(self) -> None:
        self.local_socket.close()
        self.remote_socket.close()

    def tunnel_data(
        self, src_sock: socket.socket, dest_sock: socket.socket, *, proxy_authorization: str | None = None
    ) -> bool:
        try:
            request = self.recv_data(src_sock)
        except socket.error as e:
            self.logger.error(f"Socket error during recv: {e}")
            self.close_connection()
            return True

        if not request:
            self.logger.info(f"Disconnection from {src_sock.getsockname()}. Receive 0 bytes")
            self.close_connection()
            return True

        if proxy_authorization and any(request.startswith(method) for method in (b"CONNECT", b"GET", b"POST")):
            request = self.add_auth_header(request, proxy_authorization)
            self.is_auth = True

        self.logger.info(f"Receive {len(request)} bytes from {src_sock.getsockname()}")

        try:
            self.logger.info(f"\n{request.split(b"\r\n\r\n", 1)[0].decode()}")
        except Exception:
            self.logger.info("SECURE DATA")

        if not self.is_auth:
            self.logger.error(f"Proxy Authentication Required. Disconnection from {src_sock.getsockname()}")
            self.close_connection()
            return True

        try:
            bytes_send = self.send_data(dest_sock, request)
        except socket.error as e:
            self.logger.error(f"Socket error during send: {e}")
            self.close_connection()
            return True

        if not bytes_send:
            self.logger.info(f"Disconnection from {dest_sock.getsockname()}. Send 0 bytes")
            self.close_connection()
            return True

        self.logger.info(f"Send {bytes_send} bytes to {dest_sock.getsockname()}")
        return False


class ProxyTunnel:
    def __init__(self, local_proxy: Proxy, remote_proxy: Proxy) -> None:
        self.local_proxy = local_proxy
        self.remote_proxy = remote_proxy

        self.is_close = False

        self.proxy_authorization = None
        if self.remote_proxy.username and self.remote_proxy.password:
            data = f"{self.remote_proxy.username}:{self.remote_proxy.password}"
            encoded_data = base64.b64encode(data.encode())
            self.proxy_authorization = "Basic " + encoded_data.decode()

        self.connections: list[Connection] = []
        self.server_socket = None

    def start(self, max_connections: int = 50) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.local_proxy.host, int(self.local_proxy.port)))
        self.server_socket.listen(max_connections)

        while True:
            if self.is_close:
                self.close()
                return

            for connection in self.connections.copy():
                if not connection.thread.is_alive():
                    self.connections.remove(connection)

            thread_ids = [connection.thread_id for connection in self.connections]
            if len(self.connections) == max_connections:
                continue

            local_socket, _ = self.server_socket.accept()

            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            remote_socket.connect((self.remote_proxy.host, int(self.remote_proxy.port)))

            for thread_id in range(max_connections):
                if thread_id in thread_ids:
                    continue

                connection = Connection(
                    thread_id,
                    local_socket,
                    remote_socket,
                    logging.getLogger(f"Connection_{thread_id}"),
                )

                connection.thread = Thread(target=self.handle_client, args=(connection,))
                self.connections.append(connection)

                # self.handle_client(connection)
                connection.thread.start()
                break

    def stop(self) -> None:
        self.is_close = True

    def close(self) -> None:
        for connection in self.connections:
            connection.local_socket.close()
            connection.remote_socket.close()

            if connection.thread.is_alive():
                connection.thread.kill()
                connection.thread.join()

        self.server_socket.close()

    def handle_client(self, connection: Connection) -> None:
        connection.logger.info(
            f"Connection from {connection.local_socket.getsockname()} to {connection.remote_socket.getsockname()}"
        )
        sockets = [connection.local_socket, connection.remote_socket]

        while True:
            read_sockets, _, _ = select.select(sockets, [], [])
            for sock in read_sockets:
                if sock == connection.local_socket:
                    if connection.tunnel_data(
                        sock, connection.remote_socket, proxy_authorization=self.proxy_authorization
                    ):
                        return

                if sock == connection.remote_socket:
                    if connection.tunnel_data(sock, connection.local_socket):
                        return
