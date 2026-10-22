#!/usr/bin/env python3
"""Sane4ek server agent.

Runs on every VPN server (in the `sane4ek-agent` docker container) and lets
invited Sane4ek users fetch the signed server list and get their own
AmneziaWG peer without any access to server management.

Files in DATA_DIR (/data inside the container, /opt/sane4ek on the host):
  cert.pem / key.pem   - self-signed TLS certificate (pinned by clients)
  manifest.json        - server list, written by the admin app
  manifest.sig         - base64 Ed25519 signature of manifest.json (admin key)
  invites.json         - [{"hash": sha256(token), "name", "paused", "expires", "maxDevices"}]
  registrations.json   - peers created by this agent (kept in sync with invites)
"""
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA_DIR = os.environ.get("SANE4EK_DATA", "/data")
PORT = int(os.environ.get("SANE4EK_PORT", "47443"))
DOCKER = os.environ.get("SANE4EK_DOCKER", "docker")
SYNC_INTERVAL = int(os.environ.get("SANE4EK_SYNC_INTERVAL", "60"))
USE_TLS = os.environ.get("SANE4EK_TLS", "1") == "1"

# (container, interface, config path, binary) in order of preference
AWG_TARGETS = [
    ("amnezia-awg2", "awg0", "/opt/amnezia/awg/awg0.conf", "awg"),
    ("amnezia-awg", "wg0", "/opt/amnezia/awg/wg0.conf", "wg"),
]
CLIENTS_TABLE = "/opt/amnezia/awg/clientsTable"
DNS = "1.1.1.1, 1.0.0.1"

# Interface keys copied from the server config to the client config
CLIENT_KEYS = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
               "I1", "I2", "I3", "I4", "I5",
               "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
               "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers",
               "DisableCookies"]

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
DEVICE_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

lock = threading.Lock()


def log(*args):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *args, flush=True)


# ---------------------------------------------------------------- data files
def data_path(name):
    return os.path.join(DATA_DIR, name)


def load_json(name, default):
    try:
        with open(data_path(name), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(name, value):
    tmp = data_path(name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=1)
    os.replace(tmp, data_path(name))


def find_invite(token):
    if not isinstance(token, str) or len(token) < 16:
        return None
    h = hashlib.sha256(token.encode()).hexdigest()
    for inv in load_json("invites.json", []):
        if inv.get("hash") == h:
            if inv.get("paused"):
                return None
            expires = inv.get("expires") or 0
            if expires and time.time() > expires:
                return None
            return inv
    return None


def valid_invite_hashes():
    now = time.time()
    return {inv.get("hash") for inv in load_json("invites.json", [])
            if not inv.get("paused") and not ((inv.get("expires") or 0) and now > inv["expires"])}


# ---------------------------------------------------------------- docker / awg
def docker(*args, data=None, check=True):
    r = subprocess.run([DOCKER, *args], input=data, capture_output=True, timeout=60)
    if check and r.returncode != 0:
        raise RuntimeError("docker %s failed: %s" % (args[:3], r.stderr.decode(errors="replace").strip()))
    return r.stdout.decode(errors="replace")


def running_containers():
    return set(docker("ps", "--format", "{{.Names}}").split())


def awg_target():
    names = running_containers()
    for target in AWG_TARGETS:
        if target[0] in names:
            return target
    return None


def cread(container, path):
    return docker("exec", "-i", container, "cat", path, check=False)


def cwrite(container, path, text):
    docker("exec", "-i", container, "sh", "-c", 'cat > "$0"', path, data=text.encode())


def syncconf(target):
    container, iface, conf, binary = target
    docker("exec", "-i", container, "bash", "-c",
           "%s syncconf %s <(%s-quick strip %s)" % (binary, iface, binary, conf))


def parse_server_conf(text):
    """Return (interface dict, list of peer dicts). '# I1 = x' lines count as I1."""
    iface, peers, cur = {}, [], None
    for raw in text.splitlines():
        line = raw.strip()
        if line.lower() == "[interface]":
            cur = iface
            continue
        if line.lower() == "[peer]":
            cur = {}
            peers.append(cur)
            continue
        m = re.match(r"^#\s*(I[1-5])\s*=\s*(.+)$", line)
        if m and cur is iface:
            iface.setdefault(m.group(1), m.group(2).strip())
            continue
        if not line or line.startswith("#") or "=" not in line or cur is None:
            continue
        k, v = line.split("=", 1)
        cur[k.strip()] = v.strip()
    return iface, peers


def remove_peer_blocks(text, pubkeys):
    """Remove [Peer] sections whose PublicKey is in pubkeys."""
    out, block = [], None

    def flush():
        if block is not None:
            keys = [l.split("=", 1)[1].strip() for l in block if l.strip().startswith("PublicKey")]
            if not (keys and keys[0] in pubkeys):
                out.extend(block)

    for line in text.splitlines():
        if line.strip().startswith("["):
            flush()
            block = [line] if line.strip().lower() == "[peer]" else None
            if block is None:
                out.append(line)
            continue
        if block is not None:
            block.append(line)
        else:
            out.append(line)
    flush()
    return "\n".join(out).rstrip("\n") + "\n"


def update_clients_table(container, add=None, remove=(), peers=()):
    raw = cread(container, CLIENTS_TABLE)
    try:
        table = json.loads(raw) if raw.strip() else []
        if not isinstance(table, list):
            table = []
    except ValueError:
        table = []
    if not table:
        # the admin app builds the list from the config only while the table is empty -
        # keep the clients it would have shown
        for i, p in enumerate(peers, 1):
            if p.get("PublicKey") and (not add or p["PublicKey"] != add["clientId"]):
                table.append({"clientId": p["PublicKey"], "userData": {"clientName": "Client %d" % i}})
    table = [c for c in table if c.get("clientId") not in remove]
    if add and not any(c.get("clientId") == add["clientId"] for c in table):
        table.append(add)
    cwrite(container, CLIENTS_TABLE, json.dumps(table, ensure_ascii=False, indent=4))


def allocate_ip(iface, peers):
    addr = iface.get("Address", "10.8.1.0/24").split(",")[0].strip()
    net = ipaddress.ip_interface(addr).network
    used = {ipaddress.ip_interface(addr).ip}
    for p in peers:
        for a in p.get("AllowedIPs", "").split(","):
            a = a.strip()
            if a:
                try:
                    used.add(ipaddress.ip_interface(a).ip)
                except ValueError:
                    pass
    for host in net.hosts():
        if host not in used:
            return str(host)
    raise RuntimeError("no free addresses in %s" % net)


def client_config(iface, server_pub, psk, client_ip, port):
    lines = ["[Interface]",
             "Address = %s/32" % client_ip,
             "DNS = %s" % DNS,
             "PrivateKey = __SANE4EK_PRIVATE_KEY__"]
    for k in CLIENT_KEYS:
        if iface.get(k):
            lines.append("%s = %s" % (k, iface[k]))
    lines += ["", "[Peer]",
              "PublicKey = %s" % server_pub]
    if psk:
        lines.append("PresharedKey = %s" % psk)
    lines += ["AllowedIPs = 0.0.0.0/0, ::/0",
              "Endpoint = __SANE4EK_HOST__:%s" % port,
              "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


def register(token, device, pubkey, name):
    inv = find_invite(token)
    if inv is None:
        return 403, {"error": "invite"}
    if not DEVICE_RE.match(device or "") or not KEY_RE.match(pubkey or ""):
        return 400, {"error": "bad request"}
    name = re.sub(r"[\x00-\x1f]", "", str(name or ""))[:40] or "device"

    with lock:
        target = awg_target()
        if target is None:
            return 503, {"error": "no awg"}
        container, iface_name, conf_path, _ = target

        regs = load_json("registrations.json", [])
        mine = [r for r in regs if r["tokenHash"] == inv["hash"] and r["device"] == device]
        max_devices = int(inv.get("maxDevices") or 0)
        if not mine and max_devices:
            devices = {r["device"] for r in regs if r["tokenHash"] == inv["hash"]}
            if len(devices) >= max_devices:
                return 403, {"error": "device limit"}

        text = cread(container, conf_path)
        iface, peers = parse_server_conf(text)
        if not iface.get("ListenPort"):
            return 503, {"error": "awg not configured"}
        server_pub = cread(container, "/opt/amnezia/awg/wireguard_server_public_key.key").strip()
        psk = cread(container, "/opt/amnezia/awg/wireguard_psk.key").strip()

        # forget an older key of the same device
        stale = [r["pubkey"] for r in mine if r["pubkey"] != pubkey]
        if stale:
            text = remove_peer_blocks(text, set(stale))
            iface, peers = parse_server_conf(text)
            update_clients_table(container, remove=stale)

        existing = next((p for p in peers if p.get("PublicKey") == pubkey), None)
        if existing:
            client_ip = existing.get("AllowedIPs", "").split(",")[0].split("/")[0].strip()
        else:
            client_ip = allocate_ip(iface, peers)
            block = "\n[Peer]\nPublicKey = %s\n%sAllowedIPs = %s/32\n" % (
                pubkey, ("PresharedKey = %s\n" % psk) if psk else "", client_ip)
            text = text.rstrip("\n") + "\n" + block
        if stale or not existing:
            cwrite(container, conf_path, text)
            syncconf(target)
            update_clients_table(container, peers=peers, add={
                "clientId": pubkey,
                "userData": {"clientName": "Sane4ek: %s (%s)" % (inv.get("name", ""), name),
                             "creationDate": datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")}})

        regs = [r for r in regs if not (r["tokenHash"] == inv["hash"] and r["device"] == device)]
        regs.append({"tokenHash": inv["hash"], "device": device, "pubkey": pubkey,
                     "ip": client_ip, "name": name, "time": int(time.time())})
        save_json("registrations.json", regs)
        log("registered", inv.get("name", "?"), name, client_ip)

        return 200, {"config": client_config(iface, server_pub, psk, client_ip, iface["ListenPort"])}


def sync_revoked():
    """Remove peers whose invite was deleted, paused or expired."""
    with lock:
        regs = load_json("registrations.json", [])
        valid = valid_invite_hashes()
        revoked = [r for r in regs if r["tokenHash"] not in valid]
        if not revoked:
            return
        target = awg_target()
        if target is None:
            return
        container, _, conf_path, _ = target
        keys = {r["pubkey"] for r in revoked}
        text = cread(container, conf_path)
        cwrite(container, conf_path, remove_peer_blocks(text, keys))
        syncconf(target)
        update_clients_table(container, remove=keys)
        save_json("registrations.json", [r for r in regs if r["tokenHash"] in valid])
        log("revoked", len(keys), "peer(s)")


def sync_loop():
    while True:
        try:
            sync_revoked()
        except Exception as e:  # keep the loop alive
            log("sync error:", e)
        time.sleep(SYNC_INTERVAL)


# ---------------------------------------------------------------- http
class Handler(BaseHTTPRequestHandler):
    server_version = "Sane4ek/1"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def reply(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 16384:
            return None
        try:
            return json.loads(self.rfile.read(n))
        except ValueError:
            return None

    def do_GET(self):
        if self.path == "/v1/ping":
            return self.reply(200, {"ok": True})
        return self.reply(404, {"error": "not found"})

    def do_POST(self):
        req = self.read_json()
        if not isinstance(req, dict):
            return self.reply(400, {"error": "bad request"})
        try:
            if self.path == "/v1/manifest":
                if find_invite(req.get("token")) is None:
                    return self.reply(403, {"error": "invite"})
                try:
                    with open(data_path("manifest.json"), "rb") as f:
                        manifest = f.read()
                    with open(data_path("manifest.sig"), "r") as f:
                        sig = f.read().strip()
                except OSError:
                    return self.reply(503, {"error": "no manifest"})
                return self.reply(200, {"manifest": base64.b64encode(manifest).decode(), "sig": sig})
            if self.path == "/v1/register":
                code, obj = register(req.get("token"), req.get("device"), req.get("pubkey"), req.get("name"))
                return self.reply(code, obj)
        except Exception as e:
            log("error:", e)
            return self.reply(500, {"error": "internal"})
        return self.reply(404, {"error": "not found"})


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    threading.Thread(target=sync_loop, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    if USE_TLS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(data_path("cert.pem"), data_path("key.pem"))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    log("listening on", PORT)
    httpd.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
