#!/usr/bin/env python3
"""Isolated REALITY v26.9.9 interoperability and TLS regression matrix.

See reality_xray.md. Uses only loopback listeners, disposable secrets and child
processes. Never uses a system Xray implicitly or prints process configuration.
"""

import argparse
import base64
import contextlib
import copy
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import uuid

XRAY_COMMIT = "52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120"


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def receive(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        result.extend(chunk)
    return bytes(result)


def payload_roundtrip(proxy, target):
    payload = secrets.token_bytes(256 * 1024)
    with socket.create_connection(("127.0.0.1", proxy), timeout=15) as sock:
        sock.sendall(b"\x05\x01\x00")
        assert receive(sock, 2) == b"\x05\x00", "SOCKS authentication"
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target))
        header = receive(sock, 4)
        assert header[:2] == b"\x05\x00", "SOCKS connect"
        address_size = {1: 4, 4: 16}.get(header[3])
        if header[3] == 3:
            address_size = receive(sock, 1)[0]
        assert address_size is not None, "SOCKS address type"
        receive(sock, address_size + 2)
        sock.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: "
                     + str(len(payload)).encode() + b"\r\n\r\n" + payload)
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.status == 200, "HTTP status"
        assert response.read() == payload, "payload mismatch"


class Echo(http.server.BaseHTTPRequestHandler):
    timeout = 3

    def handle(self):
        try:
            super().handle()
        except (OSError, ssl.SSLError):
            # Aborted mirrored handshakes and readiness probes are expected.
            pass

    def do_POST(self):
        payload = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


@contextlib.contextmanager
def process(binary, config, directory, name, listen):
    path = directory / (name + ".json")
    path.write_text(json.dumps(config))
    with (directory / (name + ".log")).open("w") as log:
        child = subprocess.Popen([str(binary), "run", "-c", str(path)], stdout=log, stderr=log)
        try:
            for _ in range(100):
                if child.poll() is not None:
                    raise RuntimeError(name + " exited; inspect private log locally")
                try:
                    with socket.create_connection(("127.0.0.1", listen), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError(name + " did not listen")
            yield directory / (name + ".log")
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


@contextlib.contextmanager
def workspace():
    directory = tempfile.mkdtemp(prefix="reality-matrix-")
    try:
        yield directory
    except BaseException:
        print("FAILED: private diagnostics retained at", directory, "(delete after inspection)")
        raise
    else:
        shutil.rmtree(directory)


def mldsa_matrix(args, directory, stack, xr_server, server_ports, public, short, user, target_port):
    # Xray's command emits seed and verification key. Keep both in the private
    # workspace/process configuration; never print their values.
    keys = dict(line.split(": ", 1) for line in subprocess.check_output(
        [str(args.xray), "mldsa65"], text=True).strip().splitlines())
    wrong = dict(line.split(": ", 1) for line in subprocess.check_output(
        [str(args.xray), "mldsa65"], text=True).strip().splitlines())["Verify"]
    signed_port = port()
    signed_server = copy.deepcopy(xr_server)
    signed_server["inbounds"][0]["port"] = signed_port
    signed_server["inbounds"][0]["streamSettings"]["realitySettings"]["mldsa65Seed"] = keys["Seed"]
    stack.enter_context(process(args.xray, signed_server, directory, "xr-signed-server", signed_port))
    servers = server_ports + [("xray-signed", signed_port)]
    for server_name, server_port in servers:
        for verification, verify in [("absent", ""), ("correct", keys["Verify"]), ("wrong", wrong)]:
            success = not verify or (server_name == "xray-signed" and verification == "correct")
            for client_kind, fingerprints in [("sb", ["", "chrome", "random", "randomized"]),
                                               ("xr", ["chrome"])]:
                for fingerprint in fingerprints:
                    client_port = port()
                    name = f"mldsa-{client_kind}-{server_name}-{verification}-{fingerprint or 'default'}"
                    if client_kind == "sb":
                        reality = {"enabled": True, "public_key": public, "short_id": short}
                        if verify:
                            reality["mldsa65_verify"] = verify
                        config = {"log": {"level": "error"}, "inbounds": [{"type": "socks",
                            "listen": "127.0.0.1", "listen_port": client_port}], "outbounds": [{
                            "type": "vless", "server": "127.0.0.1", "server_port": server_port,
                            "uuid": user, "tls": {"enabled": True, "server_name": "localhost",
                            "utls": {"enabled": True, "fingerprint": fingerprint}, "reality": reality}}]}
                        binary = args.sing_box
                    else:
                        reality = {"serverName": "localhost", "fingerprint": fingerprint,
                                   "password": public, "shortId": short}
                        if verify:
                            reality["mldsa65Verify"] = verify
                        config = {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1",
                            "port": client_port, "protocol": "socks", "settings": {"auth": "noauth"}}],
                            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{
                            "address": "127.0.0.1", "port": server_port, "users": [{"id": user,
                            "encryption": "none"}]}]}, "streamSettings": {"network": "tcp",
                            "security": "reality", "realitySettings": reality}}]}
                        binary = args.xray
                    with process(binary, config, directory, name, client_port):
                        iterations = 3 if fingerprint == "randomized" else 1
                        for _ in range(iterations):
                            if success:
                                payload_roundtrip(client_port, target_port)
                            else:
                                rejected_payload(client_port, target_port)
                        print("PASS", name, iterations, "payload echo(s)" if success else "rejection(s)")


def rejected_payload(proxy, target):
    # The proxy must be listening and negotiate SOCKS before the upstream probe.
    # A timeout, broken readiness probe, or payload corruption is not rejection.
    with socket.create_connection(("127.0.0.1", proxy), timeout=15) as sock:
        sock.sendall(b"\x05\x01\x00")
        assert receive(sock, 2) == b"\x05\x00", "SOCKS authentication"
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target))
        header = receive(sock, 4)
        assert header[0] == 5, "SOCKS response version"
        if header[1] != 0:
            return
        address_size = {1: 4, 4: 16}.get(header[3])
        if header[3] == 3:
            address_size = receive(sock, 1)[0]
        assert address_size is not None, "SOCKS address type"
        receive(sock, address_size + 2)
        # Xray acknowledges SOCKS before authenticating the outbound connection.
        try:
            sock.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx")
            assert sock.recv(1) == b"", "rejected connection exposed application data"
        except (ConnectionResetError, BrokenPipeError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument("--server-sing-box", type=Path, help="optional unchanged base-ref server binary")
    parser.add_argument("--ktls", action="store_true", help="require successful Linux TX/RX activation")
    args = parser.parse_args()
    args.sing_box = args.sing_box.resolve()
    args.xray = args.xray.resolve()
    server_binary = args.server_sing_box.resolve() if args.server_sing_box else args.sing_box
    version = subprocess.check_output([str(args.xray), "version"], text=True)
    assert "Xray 26.9.9" in version and XRAY_COMMIT in version, "wrong Xray version/build commit"
    print(version.splitlines()[0])
    print(subprocess.check_output([str(args.sing_box), "version"], text=True).strip())
    if server_binary != args.sing_box:
        print("Reference server:")
        print(subprocess.check_output([str(server_binary), "version"], text=True).strip())
    os.umask(0o077)
    with workspace() as tmp:
        directory = Path(tmp)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        # REALITY needs room for its 3309-byte signature in the
                        # mirrored certificate record. This is public padding.
                        "-addext", "1.2.3.4=DER:" + "00" * 5000,
                        "-keyout", str(directory / "key.pem"), "-out", str(directory / "cert.pem")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_ecdh_curve("X25519")
        context.set_alpn_protocols(["h2", "http/1.1"])
        context.load_cert_chain(directory / "cert.pem", directory / "key.pem")
        with contextlib.ExitStack() as stack:
            target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo)
            stack.callback(target.server_close)
            threading.Thread(target=target.serve_forever, daemon=True).start()
            stack.callback(target.shutdown)
            camouflage = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo)
            # REALITY leaves its mirrored TLS handshake unfinished. Defer the
            # handshake to each worker so it cannot block subsequent accepts.
            camouflage.socket = context.wrap_socket(camouflage.socket, server_side=True, do_handshake_on_connect=False)
            stack.callback(camouflage.server_close)
            threading.Thread(target=camouflage.serve_forever, daemon=True).start()
            stack.callback(camouflage.shutdown)
            target_port, handshake_port = target.server_port, camouflage.server_port
            keys = subprocess.check_output([str(args.sing_box), "generate", "reality-keypair"], text=True)
            keys = dict(line.split(": ", 1) for line in keys.strip().splitlines())
            private, public = keys["PrivateKey"], keys["PublicKey"]
            short, user = secrets.token_hex(8), str(uuid.uuid4())
            sb_port, xr_port = port(), port()
            server_tls = {"enabled": True, "server_name": "localhost", "reality": {
                "enabled": True, "private_key": private, "short_id": [short],
                "handshake": {"server": "127.0.0.1", "server_port": handshake_port}}}
            sb_server = {"log": {"level": "error"}, "inbounds": [{"type": "vless", "listen": "127.0.0.1",
                "listen_port": sb_port, "users": [{"uuid": user}], "tls": server_tls}],
                "outbounds": [{"type": "direct"}]}
            xr_server = {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": xr_port,
                "protocol": "vless", "settings": {"clients": [{"id": user}], "decryption": "none"},
                "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                    "target": "127.0.0.1:" + str(handshake_port), "serverNames": ["localhost"],
                    "privateKey": private, "shortIds": [short]}}}], "outbounds": [{"protocol": "freedom",
                        "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"], "port": str(target_port)}]}}]}
            stack.enter_context(process(server_binary, sb_server, directory, "sb-server", sb_port))
            stack.enter_context(process(args.xray, xr_server, directory, "xr-server", xr_port))
            mldsa_matrix(args, directory, stack, xr_server, [("xray", xr_port), ("sing-box", sb_port)],
                         public, short, user, target_port)
            for server_name, server_port in [("xray", xr_port), ("sing-box", sb_port)]:
                for fingerprint in ["", "chrome", "random", "randomized"]:
                    modes = [(False, False)]
                    if args.ktls and fingerprint in ["", "randomized"]:
                        modes += [(True, False), (False, True), (True, True)]
                    for tx, rx in modes:
                        client_port = port()
                        name = f"sb-{server_name}-{fingerprint or 'default'}-tx{int(tx)}-rx{int(rx)}"
                        config = {"log": {"level": "debug"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1",
                            "listen_port": client_port}], "outbounds": [{"type": "vless", "server": "127.0.0.1",
                            "server_port": server_port, "uuid": user, "tls": {"enabled": True,
                                "server_name": "localhost", "kernel_tx": tx, "kernel_rx": rx,
                                "utls": {"enabled": True, "fingerprint": fingerprint},
                                "reality": {"enabled": True, "public_key": public, "short_id": short}}}]}
                        iterations = 3 if fingerprint == "randomized" else 1
                        with process(args.sing_box, config, directory, name, client_port) as log:
                            with log.open("rb") as events:
                                for iteration in range(1, iterations + 1):
                                    # Only this fresh connection's events may satisfy the check.
                                    # Keep the client process (and its randomized seed) alive.
                                    events.seek(0, os.SEEK_END)
                                    payload_roundtrip(client_port, target_port)
                                    text = events.read()
                                    for enabled, direction in [(tx, "TX"), (rx, "RX")]:
                                        if enabled:
                                            event = f"ktls: kernel TLS {direction} enabled".encode()
                                            assert text.count(event) == 1, (
                                                f"{name} iteration {iteration}: expected one kTLS {direction} activation")
                            print("PASS", name, f"{iterations} authenticated 262144-byte echo(s)")
                client_port = port()
                config = {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": client_port,
                    "protocol": "socks", "settings": {"auth": "noauth"}}], "outbounds": [{"protocol": "vless",
                    "settings": {"vnext": [{"address": "127.0.0.1", "port": server_port,
                        "users": [{"id": user, "encryption": "none"}]}]}, "streamSettings": {
                            "network": "tcp", "security": "reality", "realitySettings": {
                                "serverName": "localhost", "fingerprint": "chrome", "password": public, "shortId": short}}}]}
                with process(args.xray, config, directory, "xr-" + server_name, client_port):
                    payload_roundtrip(client_port, target_port)
                    print("PASS xray-" + server_name, "authenticated 262144-byte echo")
            # Ordinary uTLS + ShadowTLS v3 use the same browser choices as before.
            shadow_port, plain_port = port(), port()
            password = base64.b64encode(secrets.token_bytes(16)).decode()
            config = {"log": {"level": "error"}, "inbounds": [
                {"type": "shadowtls", "listen": "127.0.0.1", "listen_port": shadow_port, "version": 3,
                 "users": [{"password": password}], "handshake": {"server": "127.0.0.1", "server_port": handshake_port},
                 "detour": "ss"},
                {"type": "shadowsocks", "tag": "ss", "method": "2022-blake3-aes-128-gcm", "password": password},
                {"type": "trojan", "listen": "127.0.0.1", "listen_port": plain_port, "users": [{"password": password}],
                 "tls": {"enabled": True, "certificate_path": str(directory / "cert.pem"), "key_path": str(directory / "key.pem")}}],
                "outbounds": [{"type": "direct"}]}
            stack.enter_context(process(args.sing_box, config, directory, "regression-server", shadow_port))
            for fingerprint in ["chrome", "firefox", "random"]:
                for kind in ["utls", "shadowtls"]:
                    client_port = port()
                    tls = {"enabled": True, "server_name": "localhost", "certificate_path": str(directory / "cert.pem"),
                           "utls": {"enabled": True, "fingerprint": fingerprint}}
                    if kind == "utls":
                        outbounds = [{"type": "trojan", "server": "127.0.0.1", "server_port": plain_port,
                                      "password": password, "tls": tls}]
                    else:
                        outbounds = [{"type": "shadowsocks", "server": "127.0.0.1", "server_port": shadow_port,
                                      "method": "2022-blake3-aes-128-gcm", "password": password, "detour": "shadow"},
                                     {"type": "shadowtls", "tag": "shadow", "server": "127.0.0.1", "server_port": shadow_port,
                                      "version": 3, "password": password, "tls": tls}]
                    config = {"log": {"level": "error"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1",
                              "listen_port": client_port}], "outbounds": outbounds}
                    name = kind + "-" + fingerprint
                    with process(args.sing_box, config, directory, name, client_port):
                        payload_roundtrip(client_port, target_port)
                        print("PASS", name, "authenticated 262144-byte echo")


if __name__ == "__main__":
    main()
