#!/usr/bin/env python3

import socket
import sys
import threading


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ("plain", "counted"):
        raise SystemExit("usage: steady_http_upstream.py PORT plain|counted")
    port = int(sys.argv[1])
    counted = sys.argv[2] == "counted"
    body = b"steady-ok"
    counter = 0
    counter_lock = threading.Lock()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(256)

    def serve():
        nonlocal counter
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                request = b""
                try:
                    while b"\r\n\r\n" not in request and len(request) < 8192:
                        part = connection.recv(1024)
                        if not part:
                            break
                        request += part
                    request_line = request.split(b"\r\n", 1)[0]
                    if not request_line:
                        continue
                    is_count = counted and b" /__count " in request_line
                    if is_count:
                        with counter_lock:
                            response_body = str(counter).encode("ascii")
                    else:
                        if counted:
                            with counter_lock:
                                counter += 1
                        response_body = body
                    response = (
                        b"HTTP/1.1 200 OK\r\nContent-Length: "
                        + str(len(response_body)).encode("ascii")
                        + b"\r\nConnection: close\r\n\r\n"
                        + response_body
                    )
                    connection.sendall(response)
                except (OSError, ValueError):
                    pass

    workers = [threading.Thread(target=serve) for _ in range(128)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()


if __name__ == "__main__":
    main()
