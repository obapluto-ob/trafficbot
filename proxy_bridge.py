#!/usr/bin/env python3
"""
Minimal SOCKS5 bridge: listens on localhost:PORT (no auth),
forwards all connections upstream via SOCKS5 with credentials.
Usage: python3 proxy_bridge.py <port> <upstream_host> <upstream_port> <user> <pass>
"""
import sys, socket, threading, struct, socks

LOCAL_PORT   = int(sys.argv[1])
UP_HOST      = sys.argv[2]
UP_PORT      = int(sys.argv[3])
UP_USER      = sys.argv[4]
UP_PASS      = sys.argv[5]

def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data: break
            dst.sendall(data)
    except: pass
    finally:
        for s in (src, dst): 
            try: s.close()
            except: pass

def handle(client):
    try:
        # SOCKS5 handshake — no auth
        hdr = client.recv(2)  # ver + nmethods
        if len(hdr) < 2: return
        nmethods = hdr[1]
        if nmethods > 0: client.recv(nmethods)  # read all method bytes
        client.sendall(b'\x05\x00')  # no auth required
        # read request
        hdr = client.recv(4)
        if len(hdr) < 4 or hdr[0] != 5 or hdr[1] != 1: return
        atyp = hdr[3]
        if atyp == 1:
            addr = socket.inet_ntoa(client.recv(4))
        elif atyp == 3:
            n = client.recv(1)[0]
            addr = client.recv(n).decode()
        else:
            return
        port = struct.unpack('!H', client.recv(2))[0]
        # connect upstream
        upstream = socks.socksocket()
        upstream.set_proxy(socks.SOCKS5, UP_HOST, UP_PORT, True, UP_USER, UP_PASS)
        upstream.connect((addr, port))
        client.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + b'\x00\x00')
        threading.Thread(target=forward, args=(client, upstream), daemon=True).start()
        threading.Thread(target=forward, args=(upstream, client), daemon=True).start()
    except Exception as e:
        try: client.close()
        except: pass

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', LOCAL_PORT))
srv.listen(32)
while True:
    client, _ = srv.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
