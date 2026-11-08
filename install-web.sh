#!/bin/sh
# Stat Scan Web v1.0.0 - optional read-only HTTPS exporter
set -eu
command -v python3 >/dev/null 2>&1 || { echo 'Нужен Python 3: apt-get install -y python3' >&2; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' 0
cat > "$stage/collector.py" <<'STAT_SCAN_COLLECTOR_PY'
#!/usr/bin/python3
"""Read-only snapshot exporter for the existing Stat Scan nftables table."""
import argparse
import fcntl
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

TABLE = "vps_guard_443"
SNAPSHOT = Path("/var/lib/stat-scan-web/snapshot.json")
CONFIG = Path("/etc/vps-guard-443.nft")
LOCK = "/run/vps-guard-443-update.lock"


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=12, check=True).stdout


def stamp(value):
    return value.isoformat(timespec="seconds") if value else None


def counted(definition, now):
    entries = definition.get("elem") or []
    if isinstance(entries, dict):
        entries = [entries]
    result = []
    for entry in entries:
        element = entry.get("elem", entry)
        if not isinstance(element, dict) or "val" not in element:
            continue
        timeout = element.get("timeout", definition.get("timeout"))
        expires = element.get("expires")
        last = None
        if (isinstance(timeout, (int, float)) and isinstance(expires, (int, float))
                and 0 <= expires <= timeout):
            last = now - timedelta(seconds=timeout - expires)
        result.append({"key": element["val"], "packets": int(element.get("counter", {}).get("packets", 0)),
                       "last_seen": stamp(last)})
    return result


def latest(rows):
    return max((row["last_seen"] for row in rows if row.get("last_seen")), default=None)


def parse_table(document, now):
    objects = document["nftables"]
    sets = {item["set"]["name"]: item["set"] for item in objects if "set" in item}
    ports = {}
    for item in objects:
        rule = item.get("rule", {})
        expressions = rule.get("expr", [])
        if rule.get("chain") != "input" or not any("drop" in x for x in expressions):
            continue
        port, version, packets = None, None, 0
        for expr in expressions:
            match = expr.get("match", {})
            payload = match.get("left", {}).get("payload", {}) if isinstance(match.get("left"), dict) else {}
            if payload.get("protocol") == "tcp" and payload.get("field") == "dport":
                port = int(match["right"])
            if payload.get("field") == "saddr" and payload.get("protocol") in ("ip", "ip6"):
                version = 4 if payload["protocol"] == "ip" else 6
            if "counter" in expr:
                packets = int(expr["counter"].get("packets", 0))
        if port is not None and version is not None:
            ports.setdefault(port, {"port": port, "ipv4": 0, "ipv6": 0, "sources": []})[f"ipv{version}"] += packets
    for port, info in ports.items():
        for version in (4, 6):
            suffix = "" if port == 443 else f"{port}_"
            for row in counted(sets.get(f"scan_hits_{suffix}v{version}", {}), now):
                info["sources"].append({"ip": str(row["key"]), "family": version,
                                        "packets": row["packets"], "last_seen": row["last_seen"]})
        info["packets"] = info["ipv4"] + info["ipv6"]
        info["last_seen"] = latest(info["sources"])
        info["sources"].sort(key=lambda r: (-r["packets"], r["ip"]))
    observed = {}
    for row in counted(sets.get("scan_observe_ports", {}), now):
        port = int(row["key"])
        observed[port] = {"port": port, "packets": row["packets"], "last_seen": row["last_seen"], "sources": []}
    for version in (4, 6):
        for row in counted(sets.get(f"scan_observe_v{version}", {}), now):
            port, address = row["key"]["concat"]
            # Different set entries can expire a moment apart. Keep details without inventing an aggregate.
            if int(port) in observed:
                observed[int(port)]["sources"].append({"ip": str(address), "family": version,
                    "packets": row["packets"], "last_seen": row["last_seen"]})
    for info in observed.values():
        info["sources"].sort(key=lambda r: (-r["packets"], r["ip"]))
    return {"protected": sorted(ports.values(), key=lambda r: r["port"]),
            "observation": sorted(observed.values(), key=lambda r: (-r["packets"], r["port"])),
            "observation_available": all(name in sets for name in ("scan_observe_ports", "scan_observe_v4", "scan_observe_v6")),
            "blacklist": {"ipv4_entries": len(sets.get("sources_v4", {}).get("elem", [])),
                          "ipv6_entries": len(sets.get("sources_v6", {}).get("elem", []))}}


def property_value(unit, prop):
    return command("/usr/bin/systemctl", "show", unit, f"--property={prop}", "--value").strip()


def collect():
    with open(LOCK, "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return None
        state = property_value("vps-guard-443.service", "ActiveState")
        now = datetime.now(timezone.utc)
        data = {"schema": 1, "agent_version": "1.0.0", "hostname": platform.node(), "captured_at": stamp(now),
                "filter_state": state, "collection_error": None, "protected": [], "observation": [],
                "observation_available": False, "blacklist": {}}
        if state in ("active", "activating", "reloading"):
            before = datetime.now(timezone.utc)
            document = json.loads(command("/usr/sbin/nft", "-j", "-nn", "list", "table", "inet", TABLE))
            after = datetime.now(timezone.utc)
            data.update(parse_table(document, before + (after - before) / 2))
            data["captured_at"] = stamp(after)
        else:
            saved = CONFIG.read_text(encoding="utf-8")
            values = sorted({int(x) for x in re.findall(r"tcp dport (\d+).*@sources_v[46].*drop", saved)})
            data["protected"] = [{"port": p, "packets": 0, "ipv4": 0, "ipv6": 0,
                                   "sources": [], "last_seen": None} for p in values]
        data["updates"] = {"automatic": property_value("vps-guard-443-update.timer", "UnitFileState") in ("enabled", "enabled-runtime"),
                           "last_result": property_value("vps-guard-443-update.service", "Result") or "unknown"}
        return data


def write_snapshot(data, path):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as out:
        temporary = Path(out.name)
        try:
            os.fchmod(out.fileno(), 0o640)
            json.dump(data, out, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            out.flush()
            os.fsync(out.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=SNAPSHOT)
    args = parser.parse_args()
    try:
        data = collect()
        if data is not None:
            write_snapshot(data, args.output)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Keep the last good data, explicitly mark failed collection rather than returning false zeroes.
        try:
            previous = json.loads(args.output.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = {"schema": 1, "hostname": platform.node(), "captured_at": None,
                        "protected": [], "observation": [], "filter_state": "unknown"}
        previous["collection_error"] = "Не удалось прочитать статистику nftables. Проверьте службу stat-scan-collect.service."
        previous["attempted_at"] = stamp(datetime.now(timezone.utc))
        write_snapshot(previous, args.output)
        print(f"Stat Scan collector: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

STAT_SCAN_COLLECTOR_PY
cat > "$stage/install_web.py" <<'STAT_SCAN_WEB_BOOTSTRAP_PY'
import argparse
import contextlib
import ipaddress
import json
import os
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

VERSION = "1.0.0"
ETC = Path("/etc/stat-scan-web")
DATA = Path("/var/lib/stat-scan-web")
LIB = Path("/usr/local/lib/stat-scan-web")
UNITS = Path("/etc/systemd/system")
ACCOUNT = "stat-scan-web"


def run(*args, **kwargs):
    return subprocess.run(args, text=True, check=True, **kwargs)


def put(path, value, mode=0o644):
    content = value.encode("utf-8") if isinstance(value, str) else value
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
        temp = Path(out.name)
        try:
            os.fchmod(out.fileno(), mode)
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)


@contextlib.contextmanager
def transaction():
    """Restore the previous endpoint files and unit state on an unsuccessful upgrade."""
    names = ("stat-scan-web.service", "stat-scan-collect.service", "stat-scan-collect.timer")
    managed = [*(ETC / n for n in ("token", "cert.pem", "key.pem", "htpasswd", "nginx.conf", "ready.html", "settings.json")),
               LIB / "collector.py", DATA / "snapshot.json", *(UNITS / n for n in names)]
    backups = {p: (p.read_bytes(), p.stat().st_mode & 0o777, p.stat().st_uid, p.stat().st_gid)
               if p.is_file() else None for p in managed}
    enabled, active = {}, {}
    for name in names:
        enabled[name] = subprocess.run(["systemctl", "is-enabled", "--quiet", name], capture_output=True).returncode == 0
        active[name] = subprocess.run(["systemctl", "is-active", "--quiet", name], capture_output=True).returncode == 0
    try:
        yield
    except BaseException:
        for name in names:
            subprocess.run(["systemctl", "stop", name], capture_output=True)
        for path, backup in backups.items():
            if backup is None:
                path.unlink(missing_ok=True)
            else:
                data, mode, uid, gid = backup
                put(path, data, mode)
                os.chown(path, uid, gid)
        for name in names:
            subprocess.run(["systemctl", "enable" if enabled[name] else "disable", name], capture_output=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        for name in names:
            if active[name]:
                subprocess.run(["systemctl", "start", name], capture_output=True)
        raise


def validate_host(value):
    value = value.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", value):
        raise ValueError("Нужен публичный IP или полное доменное имя без https:// и порта")
    return value.lower()


def nginx_configuration(port):
    return f'''worker_processes 1;
pid /run/stat-scan-web/nginx.pid;
error_log stderr warn;
events {{ worker_connections 128; }}
http {{
    access_log off;
    server_tokens off;
    client_body_temp_path /run/stat-scan-web/body;
    proxy_temp_path /run/stat-scan-web/proxy;
    fastcgi_temp_path /run/stat-scan-web/fastcgi;
    uwsgi_temp_path /run/stat-scan-web/uwsgi;
    scgi_temp_path /run/stat-scan-web/scgi;
    map $http_origin $scan_cors {{ default ""; "null" "null"; }}
    limit_req_zone $binary_remote_addr zone=scan_api:1m rate=5r/s;
    server {{
        listen 0.0.0.0:{port} ssl;
        listen [::]:{port} ssl ipv6only=on;
        ssl_certificate /etc/stat-scan-web/cert.pem;
        ssl_certificate_key /etc/stat-scan-web/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:scan_tls:1m;
        ssl_session_tickets off;
        keepalive_timeout 10s;
        client_header_timeout 10s;
        client_body_timeout 5s;
        send_timeout 10s;
        client_max_body_size 1k;
        add_header Access-Control-Allow-Origin $scan_cors always;
        add_header Access-Control-Allow-Methods "GET, HEAD, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Authorization" always;
        add_header Access-Control-Max-Age 600 always;
        add_header Vary Origin always;
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'" always;
        if ($request_method !~ ^(GET|HEAD|OPTIONS)$) {{ return 405; }}
        location = /api/v1/stats {{
            if ($request_method = OPTIONS) {{ return 204; }}
            limit_req zone=scan_api burst=15 nodelay;
            limit_req_status 429;
            auth_basic "Stat Scan";
            auth_basic_user_file /etc/stat-scan-web/htpasswd;
            default_type application/json;
            alias /var/lib/stat-scan-web/snapshot.json;
        }}
        location = / {{
            default_type text/html;
            root /etc/stat-scan-web;
            try_files /ready.html =404;
        }}
        location / {{ return 404; }}
    }}
}}
'''


SERVICE = '''[Unit]
Description=Stat Scan read-only HTTPS API
After=network.target stat-scan-collect.service
Wants=stat-scan-collect.timer
[Service]
Type=simple
User=stat-scan-web
Group=stat-scan-web
RuntimeDirectory=stat-scan-web
RuntimeDirectoryMode=0750
ExecStart=/usr/sbin/nginx -c /etc/stat-scan-web/nginx.conf -p /run/stat-scan-web -g "daemon off;"
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/run/stat-scan-web
UMask=0027
[Install]
WantedBy=multi-user.target
'''

COLLECTOR_SERVICE = '''[Unit]
Description=Read Stat Scan counters into a JSON snapshot
After=vps-guard-443.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/stat-scan-web/collector.py
TimeoutStartSec=45s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_UNIX AF_NETLINK
ReadWritePaths=/var/lib/stat-scan-web /run
UMask=0027
'''

COLLECTOR_TIMER = '''[Unit]
Description=Refresh Stat Scan snapshot every 5 seconds
[Timer]
OnBootSec=5s
OnUnitInactiveSec=5s
AccuracySec=1s
Unit=stat-scan-collect.service
[Install]
WantedBy=timers.target
'''


def main():
    parser = argparse.ArgumentParser(description="HTTPS-модуль чтения статистики для локальной HTML-панели")
    parser.add_argument("--version", action="version", version=f"Stat Scan Web v{VERSION}")
    parser.add_argument("--host", help="Публичный IP или доменное имя этого VPS")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--open-firewall", action="store_true", help="Добавить разрешение выбранного TCP-порта в активный UFW")
    parser.add_argument("--rotate-token", action="store_true")
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Запусти от root")
    lockfile = open("/run/stat-scan-web-install.lock", "a")
    import fcntl
    fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if args.uninstall:
        subprocess.run(["systemctl", "disable", "--now", "stat-scan-web.service", "stat-scan-collect.timer"], check=False)
        subprocess.run(["systemctl", "stop", "stat-scan-collect.service"], check=False)
        for name in ("stat-scan-web.service", "stat-scan-collect.service", "stat-scan-collect.timer"):
            (UNITS / name).unlink(missing_ok=True)
        for directory in (ETC, DATA, LIB):
            if directory.is_dir():
                shutil.rmtree(directory)
        run("systemctl", "daemon-reload")
        print("Модуль HTML-панели удалён. Stat Scan продолжает работать. Правило UFW, если добавляли, удалите отдельно.")
        return 0
    old = json.loads((ETC / "settings.json").read_text()) if (ETC / "settings.json").exists() else {}
    if not Path("/etc/vps-guard-443.nft").is_file() or not Path("/usr/local/sbin/stat_scan").is_file():
        parser.error("Сначала установи Stat Scan v1.1.0 или новее")
    saved = Path("/etc/vps-guard-443.nft").read_text(encoding="utf-8")
    if "chain scan_observe" not in saved:
        parser.error("Сначала обнови Stat Scan: требуется наблюдение за TCP-портами")
    host = args.host or old.get("host")
    if not host:
        with open("/dev/tty", "r+") as tty:
            tty.write("Публичный IP или домен этого VPS: ")
            tty.flush()
            host = tty.readline().strip()
    host = validate_host(host)
    port = args.port if args.port is not None else old.get("port", 9443)
    if not 1024 <= port <= 65535:
        parser.error("Для HTTPS выбери порт от 1024 до 65535")
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert и --tls-key указываются вместе")
    # Refuse a used port before changing any files on the first install or on a port change.
    if not old or old.get("port") != port:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("0.0.0.0", port))
    if not Path("/usr/sbin/nginx").exists() or not shutil.which("openssl"):
        parser.error("Нужны nginx и openssl. Установи: apt-get update && apt-get install -y nginx-core openssl")
    try:
        account = pwd.getpwnam(ACCOUNT)
    except KeyError:
        run("useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", ACCOUNT)
        account = pwd.getpwnam(ACCOUNT)
    for directory in (ETC, DATA):
        directory.mkdir(exist_ok=True)
        os.chown(directory, 0, account.pw_gid)
        os.chmod(directory, 0o2750)
    LIB.mkdir(parents=True, exist_ok=True)
    os.chmod(LIB, 0o755)
    with transaction():
        token_path = ETC / "token"
        token = token_path.read_text().strip() if token_path.exists() and not args.rotate_token else secrets.token_urlsafe(32)
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
            raise ValueError("Некорректный сохранённый ключ. Повтори установку с --rotate-token")
        with tempfile.TemporaryDirectory(prefix="stat-scan-web-", dir="/etc") as staging:
            stage = Path(staging)
            cert, key = stage / "cert.pem", stage / "key.pem"
            if args.tls_cert:
                shutil.copyfile(args.tls_cert, cert)
                shutil.copyfile(args.tls_key, key)
            elif (ETC / "cert.pem").exists() and old.get("host") == host:
                shutil.copyfile(ETC / "cert.pem", cert)
                shutil.copyfile(ETC / "key.pem", key)
            else:
                try:
                    ipaddress.ip_address(host)
                    san = f"IP:{host}"
                except ValueError:
                    san = f"DNS:{host}"
                run("openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes", "-days", "825",
                    "-subj", "/CN=Stat Scan", "-addext", f"subjectAltName={san}", "-keyout", str(key), "-out", str(cert),
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            # Check certificate/key pair before replacing live credentials.
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert), str(key))
            try:
                ipaddress.ip_address(host)
                verify_option = "-checkip"
            except ValueError:
                verify_option = "-checkhost"
            run("openssl", "x509", "-in", str(cert), "-noout", verify_option, host, capture_output=True)
            htpasswd = run("openssl", "passwd", "-6", "-stdin", input=token + "\n", capture_output=True).stdout.strip()
            put(ETC / "cert.pem", cert.read_bytes(), 0o640)
            put(ETC / "key.pem", key.read_bytes(), 0o640)
            put(ETC / "htpasswd", f"scan:{htpasswd}\n", 0o640)
        put(token_path, token + "\n", 0o600)
        put(ETC / "nginx.conf", nginx_configuration(port))
        put(ETC / "ready.html", '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Stat Scan API</title><style>body{font:18px system-ui;max-width:650px;margin:12vh auto;padding:24px;color:#163146;background:#f2f7fc}p{line-height:1.6}</style><h1>Stat Scan · соединение готово</h1><p>HTTPS работает. Вернитесь в локальную HTML-панель и нажмите «Обновить».</p><p>Статистика доступна только с ключом доступа.</p></html>')
        put(LIB / "collector.py", Path(__file__).with_name("collector.py").read_bytes())
        put(ETC / "settings.json", json.dumps({"host": host, "port": port, "version": VERSION}), 0o600)
        for name, body in (("stat-scan-web.service", SERVICE), ("stat-scan-collect.service", COLLECTOR_SERVICE), ("stat-scan-collect.timer", COLLECTOR_TIMER)):
            put(UNITS / name, body)
        run("systemctl", "daemon-reload")
        run("systemctl", "start", "stat-scan-collect.service")
        # Test the exact config as the unprivileged service user before restarting the endpoint.
        runtime = Path("/run/stat-scan-web")
        runtime.mkdir(exist_ok=True)
        os.chown(runtime, account.pw_uid, account.pw_gid)
        run("runuser", "-u", ACCOUNT, "--", "/usr/sbin/nginx", "-t", "-c", str(ETC / "nginx.conf"), "-p", str(runtime))
        run("systemctl", "enable", "stat-scan-web.service", "stat-scan-collect.timer")
        run("systemctl", "start", "stat-scan-collect.timer")
        run("systemctl", "restart", "stat-scan-web.service")
        run("systemctl", "is-active", "--quiet", "stat-scan-web.service")
    if args.open_firewall:
        ufw = shutil.which("ufw")
        if ufw and "Status: active" in run(ufw, "status", capture_output=True, env={**os.environ, "LC_ALL": "C"}).stdout:
            run(ufw, "allow", f"{port}/tcp", "comment", "Stat Scan read-only API")
        else:
            print(f"UFW не активен. При необходимости разреши TCP {port} в фаерволе провайдера.")
    address = f"[{host}]" if ":" in host else host
    fingerprint = run("openssl", "x509", "-in", str(ETC / "cert.pem"), "-noout", "-fingerprint", "-sha256", capture_output=True).stdout.strip()
    print(f"\nStat Scan Web v{VERSION} установлен.\nАдрес API: https://{address}:{port}\nКлюч доступа: {token}\n{fingerprint}")
    print(f"\nОткрой этот HTTPS-адрес в браузере. Если сертификат самоподписанный, сравни отпечаток и добавь исключение.\nЗатем добавь адрес и ключ в stat-scan.html.\nКлюч можно посмотреть: cat /etc/stat-scan-web/token")
    if not args.open_firewall:
        print(f"Если соединение блокируется UFW: ufw allow {port}/tcp comment 'Stat Scan read-only API'")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Ошибка установки: {error}", file=sys.stderr)
        raise SystemExit(1)

STAT_SCAN_WEB_BOOTSTRAP_PY
python3 "$stage/install_web.py" "$@"
