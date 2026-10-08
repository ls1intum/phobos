#!/usr/bin/env python3
"""The stand-in server of record_networked.sh: TLS for api.phobos.test, a plain port and a resolver.

It listens on 443 with a self-signed certificate for api.phobos.test (made at start with openssl and
kept in a temporary directory), on 8443 in plain text, and on 53/udp answering an A query for
api.phobos.test with its own address and every other query with no answer. Standard library only.
The suite starts it on a Docker network that has no route out, so nothing here can reach beyond it.
"""

from __future__ import annotations

import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading

NAME = "api.phobos.test"
TLS_PORT = 443
PLAIN_PORT = 8443
DNS_PORT = 53
RESPONSE = b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nOK-NET"


class Answerer(socketserver.BaseRequestHandler):
    """Answers one DNS query: the server's address for NAME, an empty answer for anything else."""

    def handle(self) -> None:
        """Replies to a datagram holding one question."""
        data, sock = self.request
        if len(data) < 12:
            return
        question_end = 12
        labels = []
        while question_end < len(data) and data[question_end] != 0:
            length = data[question_end]
            labels.append(data[question_end + 1:question_end + 1 + length].decode("ascii", "replace"))
            question_end += 1 + length
        question_end += 5
        asked = ".".join(labels).lower()
        question = data[12:question_end]
        if asked == NAME and question[-4:-2] == b"\x00\x01":
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ADDRESS)
            header = struct.pack("!HHHHHH", struct.unpack("!H", data[:2])[0], 0x8180, 1, 1, 0, 0)
            sock.sendto(header + question + answer, self.client_address)
        else:
            header = struct.pack("!HHHHHH", struct.unpack("!H", data[:2])[0], 0x8180, 1, 0, 0, 0)
            sock.sendto(header + question, self.client_address)


def serve_plain() -> None:
    """Answers every connection on the plain port with the same short response."""
    listener = socket.create_server(("0.0.0.0", PLAIN_PORT))
    while True:
        connection, _ = listener.accept()
        connection.sendall(RESPONSE)
        connection.close()


def serve_tls(certificate: str, key: str) -> None:
    """Answers every TLS connection on the TLS port with the same short response."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    listener = socket.create_server(("0.0.0.0", TLS_PORT))
    while True:
        connection, _ = listener.accept()
        try:
            with context.wrap_socket(connection, server_side=True) as secured:
                secured.recv(4096)
                secured.sendall(RESPONSE)
        except (ssl.SSLError, OSError):
            connection.close()


ADDRESS = socket.gethostbyname(socket.gethostname())


def main() -> None:
    """Makes the certificate, starts the three listeners and serves until it is stopped."""
    directory = tempfile.mkdtemp(prefix="record-network-server.")
    certificate = f"{directory}/certificate.pem"
    key = f"{directory}/key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", f"/CN={NAME}",
                    "-addext", f"subjectAltName=DNS:{NAME}", "-keyout", key, "-out", certificate],
                   check=True, capture_output=True)
    threading.Thread(target=serve_tls, args=(certificate, key), daemon=True).start()
    threading.Thread(target=serve_plain, daemon=True).start()
    with socketserver.UDPServer(("0.0.0.0", DNS_PORT), Answerer) as resolver:
        print(f"serving {NAME} at {ADDRESS}", flush=True)
        resolver.serve_forever()


if __name__ == "__main__":
    main()
