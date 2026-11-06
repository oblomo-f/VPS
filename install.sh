#!/usr/bin/env bash
# Stat Scan v1.0.0
set -euo pipefail

if ! command -v python3 >/dev/null; then
    printf '%s\n' 'Для установки нужен Python 3. На Ubuntu/Debian: apt-get install python3 nftables ca-certificates' >&2
    exit 1
fi

stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT

cat > "$stage/stat_scan-menu.py" <<'STAT_SCAN_MENU_PY'
#!/usr/bin/python3
import argparse
import contextlib
import fcntl
import hashlib
import io
import json
import os
import re
import runpy
import subprocess
import sys
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from shutil import get_terminal_size
from tempfile import NamedTemporaryFile
from typing import NamedTuple
from zoneinfo import ZoneInfo

TABLE = "vps_guard_443"
CONFIG = Path("/etc/vps-guard-443.nft")
COMMAND = Path("/usr/local/sbin/stat_scan")
UPDATER = Path("/usr/local/sbin/vps-guard-443-update.py")
OLD_UPDATER = "49b4122d4d170060113254c8dd647db0a6ecc59b337776862cf928a1c8692e41"
LOCK = "/run/vps-guard-443-update.lock"
GUARD = "vps-guard-443.service"
SERVICE = "vps-guard-443-update.service"
TIMER = "vps-guard-443-update.timer"
UNIT_DIR = Path("/etc/systemd/system")
EXPORT_DIR = Path("/root")
FAMILIES = {4: "ip", 6: "ip6"}
CHAIN = "    chain input {\n"
CHAIN_POLICY = "        type filter hook input priority -5; policy accept;\n"
RULE_HEAD = re.compile(
    r'iifname != "lo" ct state new tcp dport (\d+) (ip6?) saddr @sources_v([46]) (.+)'
)
DROP = re.compile(r"counter(?: packets (\d+) bytes \d+)? drop")
RULE_KEYS = {(version, kind) for version in FAMILIES for kind in ("track", "drop")}
ERRORS = (KeyError, StopIteration, TypeError, ValueError, OSError, subprocess.SubprocessError)
ANSI_COLOR = re.compile(r"(\x1b\[[0-9;]*m)")


class Rule(NamedTuple):
    line: str
    handle: str
    packets: int


def nft(*args, data=None):
    return subprocess.run(
        ["/usr/sbin/nft", *args], input=data, text=True,
        capture_output=True, check=True,
    ).stdout


def set_name(port, version):
    suffix = "" if port == 443 else f"{port}_"
    return f"scan_hits_{suffix}v{version}"


def set_definition(port, version):
    name = set_name(port, version)
    return f"{name} {{ type ipv{version}_addr; flags dynamic,timeout; timeout 1d; size 4096; }}"


def rule_texts(port, version):
    family = FAMILIES[version]
    prefix = f'iifname != "lo" ct state new tcp dport {port} {family} saddr @sources_v{version}'
    return (
        f"{prefix} update @{set_name(port, version)} {{ {family} saddr counter }}",
        f"{prefix} counter drop",
    )


def read_ports(text):
    ports = {}
    for line in text.splitlines(keepends=True):
        if "@sources_v" not in line:
            continue
        rule, _, handle = line.strip().partition(" # handle ")
        match = RULE_HEAD.fullmatch(rule)
        if not match:
            raise ValueError("Обнаружено незнакомое правило фильтра подсетей")
        raw_port, family, raw_version, statement = match.groups()
        port, version = int(raw_port), int(raw_version)
        if FAMILIES[version] != family:
            raise ValueError(f"Правило TCP {port} содержит несовпадающие семейства IP")
        drop = DROP.fullmatch(statement)
        if drop:
            key = (version, "drop")
            packets = int(drop[1] or 0)
        elif statement.startswith(f"update @{set_name(port, version)} "):
            key = (version, "track")
            packets = 0
        else:
            raise ValueError(f"Обнаружено незнакомое действие на TCP {port}")
        rules = ports.setdefault(port, {})
        if key in rules:
            raise ValueError(f"Обнаружены повторяющиеся правила на TCP {port}")
        rules[key] = Rule(line, handle, packets)
    for port, rules in ports.items():
        if rules.keys() != RULE_KEYS:
            raise ValueError(f"Комплект правил TCP {port} неполный")
    return ports


def live_ports():
    return read_ports(nft("-a", "list", "chain", "inet", TABLE, "input"))


def saved_ports():
    return read_ports(CONFIG.read_text(encoding="utf-8"))


def atomic_write(path, content, mode):
    with NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as staged:
        temp = Path(staged.name)
        try:
            os.fchmod(staged.fileno(), mode)
            staged.write(content)
            staged.flush()
            os.fsync(staged.fileno())
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)


def config_for_port(original, rules, port, enable):
    sets = [f"    set {set_definition(port, v)}\n" for v in FAMILIES]
    if enable:
        if original.count(CHAIN) != 1 or original.count(CHAIN_POLICY) != 1:
            raise ValueError(f"Не удалось найти цепочку input в {CONFIG}")
        added = "".join(f"        {rule}\n" for v in FAMILIES for rule in rule_texts(port, v))
        return original.replace(CHAIN, "".join(sets) + CHAIN, 1).replace(CHAIN_POLICY, CHAIN_POLICY + added, 1)

    for line in sets + [rule.line for rule in rules.values()]:
        if original.count(line) != 1:
            raise ValueError(f"Не удалось найти точное правило или набор TCP {port} в {CONFIG}")
        original = original.replace(line, "", 1)
    return original


def port_transaction(port, rules, enable):
    commands = []
    if enable:
        for version in FAMILIES:
            commands.append(f"create set inet {TABLE} {set_definition(port, version)}")
            commands.extend(
                f"add rule inet {TABLE} input {rule}" for rule in rule_texts(port, version)
            )
    else:
        for rule in rules.values():
            if not rule.handle.isdecimal():
                raise ValueError(f"Не удалось определить номер правила TCP {port}")
            commands.append(f"delete rule inet {TABLE} input handle {rule.handle}")
        commands.extend(f"delete set inet {TABLE} {set_name(port, v)}" for v in FAMILIES)
    return "\n".join(commands) + "\n"


def change_port(port, enable):
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        original = CONFIG.read_text(encoding="utf-8")
        saved = read_ports(original)
        active = live_ports() if filter_active() else None
        if active is not None and (saved.keys() ^ active.keys()) - {port}:
            raise ValueError("Список активных портов отличается от сохранённого")
        save_needed = (port in saved) != enable
        apply_needed = active is not None and (port in active) != enable
        if not save_needed and not apply_needed:
            print(f"TCP {port} уже добавлен." if enable else f"TCP {port} отсутствует в списке.")
            return

        updated = config_for_port(original, saved.get(port, {}), port, enable) if save_needed else original
        if save_needed:
            nft("-c", "-f", "-", data=updated)
        if apply_needed:
            batch = port_transaction(port, active.get(port, {}), enable)
            nft("-c", "-f", "-", data=batch)
        if save_needed:
            atomic_write(CONFIG, updated.encode("utf-8"), 0o600)
        try:
            if apply_needed:
                nft("-f", "-", data=batch)
        except (OSError, subprocess.SubprocessError):
            if save_needed:
                atomic_write(CONFIG, original.encode("utf-8"), 0o600)
            raise

    print(f"TCP {port} добавлен в фильтр." if enable else f"TCP {port} удалён из фильтра.")


def list_ports():
    ports = sorted(live_ports() if filter_active() else saved_ports())
    print("\nПорты в фильтре")
    if not ports:
        print("  Список пуст.")
    for port in ports:
        print(f"  {port}/tcp")


def choose_port(enable, ask):
    verb = "добавить" if enable else "удалить"
    value = ask(f"Какой TCP-порт {verb}? Enter — отмена: ").strip()
    if not value:
        return
    if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 65535:
        raise ValueError("Введи номер TCP-порта от 1 до 65535")
    change_port(int(value), enable)


def source_counts(port, version):
    name = set_name(port, version)
    output = json.loads(nft("-j", "-nn", "list", "set", "inet", TABLE, name))
    entries = next(item["set"].get("elem") for item in output["nftables"] if "set" in item) or []
    if isinstance(entries, dict):
        entries = [entries]
    return [
        (entry["elem"]["val"], entry["elem"]["counter"]["packets"])
        for entry in entries
    ]


def statistics():
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        if not filter_active():
            ports = saved_ports()
            return ports, {port: [] for port in ports}
        ports = live_ports()
        sources = {
            port: sorted(
                (row for v in FAMILIES for row in source_counts(port, v)),
                key=lambda row: (-row[1], row[0]),
            )
            for port in ports
        }
    return ports, sources


def report(show_all=False):
    if not filter_active():
        print("Фильтр остановлен. Запуск — пункт 4.1.")
        return
    ports, sources = statistics()
    if not ports:
        print("\nВ фильтре пока нет TCP-портов.")
        return
    totals = {
        port: {str(v): rules[(v, "drop")].packets for v in FAMILIES}
        for port, rules in ports.items()
    }
    if len(ports) > 1:
        ipv4 = sum(counts["4"] for counts in totals.values())
        ipv6 = sum(counts["6"] for counts in totals.values())
        print(f"\nВсего по {len(ports)} TCP-портам · {ipv4 + ipv6} пакетов · IPv4 {ipv4} · IPv6 {ipv6}")
    for port in sorted(ports):
        display_report(port, totals[port], sources[port], show_all)
    print("  IP хранятся 24 ч после последнего совпадения.")
    print("  Повторы SYN входят в счётчик.")


def paint(text, style):
    if (
        style and sys.stdout.isatty()
        and os.environ.get("TERM", "dumb") != "dumb"
        and "NO_COLOR" not in os.environ
    ):
        return f"\033[{style}m{text}\033[0m"
    return text

def display_report(port, totals, rows, show_all):
    def number(value):
        return f"{int(value):,}".replace(",", " ")

    total = int(totals["4"]) + int(totals["6"])
    summary = f"Отброшено {number(total)}     IPv4 {number(totals['4'])}     IPv6 {number(totals['6'])}"
    shown = [(address, number(packets)) for address, packets in (rows if show_all else rows[:20])]
    packet_width = max([len("Пакеты"), *(len(packets) for _, packets in shown)])
    address_width = max([len("IP-адрес"), *(len(address) for address, _ in shown)])
    width = max(52, len(summary), address_width + packet_width + 2)
    address_width = width - packet_width - 2

    def edge(left, right, title=""):
        label = f"─ {title} " if title else ""
        print(left + paint(label, "1;36") + "─" * (width + 2 - len(label)) + right)

    def line(text, style=""):
        print(f"│ {paint(text.ljust(width), style)} │")

    title = "VLESS · TCP 443" if port == 443 else f"TCP {port}"
    edge("╭", "╮", title)
    line(summary, "1;33")
    edge("├", "┤", f"Источники · {number(len(rows))}")
    if shown:
        line(f"{'IP-адрес':<{address_width}}  {'Пакеты':>{packet_width}}", "1;36")
        for address, packets in shown:
            line(f"{address:<{address_width}}  {packets:>{packet_width}}")
    else:
        line("Записей по IP пока нет.")
    edge("╰", "╯")
    if len(rows) > len(shown):
        print(f"  Показано {len(shown)} из {number(len(rows))} · stat_scan --all")


def reset_statistics(by_ip, ask):
    if not filter_active():
        print("Фильтр остановлен. Статистика появится после запуска.")
        return
    target = "записи по IP" if by_ip else "счётчики портов"
    answer = ask(f"Сбросить {target} для всех портов? [д/Н]: ").strip().casefold()
    if answer not in {"д", "да", "y", "yes"}:
        print("Сброс отменён.")
        return
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not filter_active():
            print("Фильтр остановлен.")
            return
        ports = live_ports()
        if not ports:
            print("В фильтре пока нет TCP-портов.")
            return
        commands = []
        for port, rules in ports.items():
            for version in FAMILIES:
                if by_ip:
                    commands.append(f"flush set inet {TABLE} {set_name(port, version)}")
                else:
                    handle = rules[(version, "drop")].handle
                    if not handle.isdecimal():
                        raise ValueError(f"Не удалось определить номер правила TCP {port}")
                    _, drop = rule_texts(port, version)
                    commands.append(f"replace rule inet {TABLE} input handle {handle} {drop}")
        batch = "\n".join(commands) + "\n"
        nft("-c", "-f", "-", data=batch)
        nft("-f", "-", data=batch)
    print(f"Сброшены {target}.")


def save_ips():
    _, sources = statistics()
    addresses = {ip_address(address) for rows in sources.values() for address, _ in rows}
    ordered = sorted(addresses, key=lambda address: (address.version, int(address)))
    content = "".join(f"{address}\n" for address in ordered).encode("ascii")
    stamp = datetime.now(ZoneInfo("Europe/Moscow")).strftime("%Y%m%d-%H%M%S-%f")
    destination = EXPORT_DIR / f"stat_scan-ips-{stamp}.txt"
    atomic_write(destination, content, 0o600)
    print(f"Сохранено адресов — {len(ordered)}\n{destination}")


def systemctl(*args, check=True):
    return subprocess.run(
        ["/usr/bin/systemctl", *args], capture_output=True, text=True, check=check,
    )


def filter_active():
    return systemctl("is-active", "--quiet", GUARD, check=False).returncode == 0


def guard_status():
    if filter_active():
        return paint("● ФИЛЬТР АКТИВЕН", "1;32")
    return paint("○ ФИЛЬТР ОСТАНОВЛЕН", "1;31")


def control_filter(enable):
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        systemctl("start" if enable else "stop", GUARD)
    print(guard_status())


def ip_policy_view():
    updater = runpy.run_path(str(UPDATER))
    original = CONFIG.read_text(encoding="utf-8")
    policy = updater["read_policy"](original, updater["configured_sources"](original))
    for heading, addresses in (("Ручные добавления", policy.block), ("Исключения", policy.exclude)):
        print(paint(f"  {heading} · {len(addresses)}", "1;36"))
        for address in sorted(addresses, key=lambda ip: (ip.version, int(ip))):
            print(f"  {address}")


def edit_ip(block, ask):
    prompt = "Какой IP добавить в blacklist?" if block else "Какой IP исключить из blacklist?"
    address = ask(f"{prompt} Enter — отмена: ").strip()
    if not address:
        return
    updater = runpy.run_path(str(UPDATER))
    address = updater["change_ip"](address, block)
    print(f"IP {address} добавлен в blacklist." if block else f"IP {address} исключён из blacklist.")


def remove_filter(ask):
    answer = ask("Удалить фильтр, настройки и stat_scan? [д/н]: ").strip().casefold()
    if answer not in {"д", "да", "y", "yes"}:
        print("Удаление отменено.")
        return False

    if (UNIT_DIR / TIMER).exists():
        systemctl("disable", "--now", TIMER)
    if (UNIT_DIR / SERVICE).exists():
        systemctl("stop", SERVICE)
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (UNIT_DIR / GUARD).exists():
            systemctl("disable", "--now", GUARD)
        nft("destroy", "table", "inet", TABLE)
        for unit in (TIMER, SERVICE, GUARD):
            (UNIT_DIR / unit).unlink(missing_ok=True)
        systemctl("daemon-reload")
        CONFIG.unlink(missing_ok=True)
        UPDATER.unlink(missing_ok=True)
        COMMAND.unlink(missing_ok=True)
    print("Фильтр и команда stat_scan удалены.")
    return True


def timer_status():
    states = [
        subprocess.run(
            ["/usr/bin/systemctl", action, TIMER], capture_output=True, text=True
        ).stdout.strip()
        for action in ("is-enabled", "is-active")
    ]
    if states == ["enabled", "active"]:
        return paint("● Автообновление включено", "1;32") + " · 04:30 МСК"
    if states == ["disabled", "inactive"]:
        return paint("○ Автообновление выключено", "1;31")
    return f"Таймер · автозагрузка {states[0] or 'неизвестно'} · состояние {states[1] or 'неизвестно'}"


def manual_update():
    result = subprocess.run(["/usr/bin/systemctl", "start", SERVICE], capture_output=True, text=True)
    journal = subprocess.run(
        ["/usr/bin/journalctl", "-u", SERVICE, "-n", "5", "--no-pager", "-o", "cat"],
        capture_output=True, text=True, check=True,
    )
    print(journal.stdout.strip())
    result.check_returncode()


def set_timer(enable):
    action = "enable" if enable else "disable"
    subprocess.run(["/usr/bin/systemctl", action, "--now", TIMER], capture_output=True, text=True, check=True)
    print(timer_status())


def dashboard_statistics():
    if not filter_active():
        print("  Фильтр остановлен. Запуск — пункт 4.1.")
        return
    ports, sources = statistics()
    if not ports:
        print("В фильтре пока нет TCP-портов.")
        return
    totals = {
        port: [rules[(version, "drop")].packets for version in FAMILIES]
        for port, rules in ports.items()
    }
    ipv4 = sum(counts[0] for counts in totals.values())
    ipv6 = sum(counts[1] for counts in totals.values())
    print(paint(f"  Отброшено {ipv4 + ipv6} · IPv4 {ipv4} · IPv6 {ipv6}", "1;33"))
    print(paint(f"  {'Порт':<11}{'Пакеты':>10}{'IPv4':>9}{'IPv6':>9}{'IP':>7}", "1;36"))
    print("  " + "─" * 46)
    for port in sorted(ports):
        v4, v6 = totals[port]
        print(f"  {f'{port}/tcp':<11}{v4 + v6:>10}{v4:>9}{v6:>9}{len(sources[port]):>7}")

    shown = [(port, address, packets) for port in sorted(ports) for address, packets in sources[port][:20]]
    print()
    if shown:
        address_width = max(24, max(len(address) for _, address, _ in shown))
        print(paint(f"  {'Порт':<11}{'IP-адрес':<{address_width}}{'Пакеты':>9}", "1;36"))
        for port, address, packets in shown:
            print(f"  {f'{port}/tcp':<11}{address:<{address_width}}{packets:>9}")
        if len(shown) < sum(map(len, sources.values())):
            print("  До 20 IP на порт · полный отчёт: stat_scan --all")
    else:
        print("  Записей по IP пока нет.")
    print("  IP хранятся 24 ч · повторы SYN учитываются.")


class ScreenBuffer(io.StringIO):
    def isatty(self):
        return True


def capture(action):
    buffer = ScreenBuffer()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        try:
            action()
        except ERRORS as error:
            details = (getattr(error, "stderr", None) or str(error)).strip()
            print(paint(f"Ошибка: {details}", "1;31"))
    return buffer.getvalue().strip("\n").splitlines()


def clip_line(text, width):
    output = []
    colored = False
    for piece in ANSI_COLOR.split(text.expandtabs(2)):
        if ANSI_COLOR.fullmatch(piece):
            output.append(piece)
            colored = True
            continue
        safe = "".join(character for character in piece if character.isprintable())
        output.append(safe[:width])
        width -= len(safe)
        if width <= 0:
            break
    if colored:
        output.append("\033[0m")
    return "".join(output)


def frame(section, sections, status, notice, body, page, columns, rows):
    width = max(1, columns - 1)
    bar_width = min(66, width)
    ruler = paint("═" * bar_width, "36")
    nav = []
    for key, label in (
        ("1", "Статистика"), ("2", "Порты"), ("3", "Обновление"),
        ("4", "Фильтр"), ("5", "Настройки IP"), ("6", "Удалить фильтр"), ("0", "Выход"),
    ):
        style = "1;30;46" if key == section else "1;31" if key == "6" else "1;36"
        nav.append(paint(f" {key} {label} ", style))
    groups = (nav[:3], nav[3:]) if width >= 62 else (nav[:2], nav[2:4], nav[4:6], nav[6:])
    nav_lines = ["  " + "  ".join(group) for group in groups]
    title, actions, _ = sections[section]
    heading = paint("Stat Scan".center(bar_width), "1;36")
    masthead = [ruler, heading, ruler] if rows >= 16 else [heading]
    divider = [paint("─" * bar_width, "36")] if rows >= 16 else []
    header = [
        *masthead,
        f"  Статус: {status}",
        *nav_lines,
        *divider,
        paint(f"  {title}", "1;36"),
        *[f"  {section}.{index}) {label}" for index, (label, _) in enumerate(actions, 1)],
        "",
    ][:max(1, rows - 4)]
    content = notice + ([""] if notice and body else []) + body
    capacity = max(1, rows - len(header) - 3)
    pages = max(1, (len(content) + capacity - 1) // capacity)
    page = min(max(0, page), pages - 1)
    visible = content[page * capacity:(page + 1) * capacity]
    footer = [paint(f"  Страница {page + 1}/{pages} · + дальше · - назад", "1;36")] if pages > 1 else []
    return [clip_line(line, width) for line in header + visible + footer], page, pages


def dashboard():
    sections = {
        "1": ("Статистика", [
            ("Сбросить статистику по портам", lambda ask: reset_statistics(False, ask)),
            ("Сбросить статистику по IP", lambda ask: reset_statistics(True, ask)),
            ("Сохранить IP в файл", lambda ask: save_ips()),
        ], dashboard_statistics),
        "2": ("Порты", [
            ("Список портов", lambda ask: list_ports()),
            ("Добавить порт", lambda ask: choose_port(True, ask)),
            ("Удалить порт", lambda ask: choose_port(False, ask)),
        ], list_ports),
        "3": ("Обновление", [
            ("Ручное обновление · Обновить", lambda ask: manual_update()),
            ("Автоматическое обновление · Включить", lambda ask: set_timer(True)),
            ("Автоматическое обновление · Выключить", lambda ask: set_timer(False)),
        ], lambda: print(timer_status())),
        "4": ("Меню фильтра", [
            ("Запустить фильтр", lambda ask: control_filter(True)),
            ("Остановить фильтр", lambda ask: control_filter(False)),
        ], lambda: print(guard_status())),
        "5": ("Настройки IP", [
            ("Добавить IP в blacklist", lambda ask: edit_ip(True, ask)),
            ("Удалить IP из blacklist", lambda ask: edit_ip(False, ask)),
        ], ip_policy_view),
    }
    terminal = sys.stdout
    ansi = os.environ.get("TERM", "dumb") != "dumb"
    section, page, pages = "1", 0, 1
    notice = []
    body = capture(sections[section][2])
    removed = False

    def ask(prompt):
        nonlocal page, pages
        with contextlib.redirect_stdout(terminal):
            size = get_terminal_size()
            status = capture(lambda: print(guard_status()))
            lines, page, pages = frame(
                section, sections, " ".join(status), notice, body,
                page, size.columns, size.lines,
            )
            terminal.write(("\033[H\033[2J" if ansi else "\n") + "\n".join(lines) + "\n")
            terminal.flush()
            return input(clip_line(prompt, max(1, size.columns - 1))).strip()

    def uninstall():
        nonlocal removed
        removed = remove_filter(ask)

    if ansi:
        terminal.write("\033[?1049h")
        terminal.flush()
    try:
        while True:
            choice = ask("Выберите действие: ")
            if choice == "0":
                return
            if choice == "6":
                notice = capture(uninstall)
                if removed:
                    break
                page = 0
                continue
            if choice in sections:
                section, page, notice = choice, 0, []
                body = capture(sections[section][2])
                continue
            if choice in {"+", "-"}:
                page = min(max(page + (1 if choice == "+" else -1), 0), pages - 1)
                continue

            actions = {f"{section}.{i}": action for i, (_, action) in enumerate(sections[section][1], 1)}
            if choice not in actions:
                if not choice:
                    body = capture(sections[section][2])
                else:
                    page, notice = 0, ["Выбери раздел или действие с номером из списка."]
                continue
            notice = capture(lambda: actions[choice](ask))
            body = capture(sections[section][2])
            if notice == body:
                notice = []
            page = 0
    finally:
        if ansi:
            terminal.write("\033[0m\033[?1049l")
            terminal.flush()
    if removed:
        print("\n".join(notice))


def install():
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not COMMAND.is_file():
            raise ValueError("Сначала установи исходную команду stat_scan")
        saved = saved_ports()
        if filter_active() and saved.keys() != live_ports().keys():
            raise ValueError("Список активных портов отличается от сохранённого")
        incoming = Path(__file__).with_name(UPDATER.name).read_bytes()
        compile(incoming, str(UPDATER), "exec")
        previous = UPDATER.read_bytes()
        if previous != incoming and hashlib.sha256(previous).hexdigest() != OLD_UPDATER:
            raise ValueError("На VPS установлена другая версия обновлятора")

        unit = UNIT_DIR / SERVICE
        unit_before = unit.read_bytes()
        unit_after = unit_before.replace(f"Requisite={GUARD}\n".encode(), b"", 1)
        updater_changed = previous != incoming
        unit_changed = unit_before != unit_after
        try:
            if updater_changed:
                atomic_write(UPDATER, incoming, 0o644)
            if unit_changed:
                atomic_write(unit, unit_after, 0o644)
                systemctl("daemon-reload")
            atomic_write(COMMAND, Path(__file__).read_bytes(), 0o755)
        except (OSError, subprocess.SubprocessError):
            if updater_changed:
                atomic_write(UPDATER, previous, 0o644)
            if unit_changed:
                atomic_write(unit, unit_before, 0o644)
                systemctl("daemon-reload")
            raise
    print("Меню stat_scan установлено.")


def main():
    parser = argparse.ArgumentParser(description="Статистика и управление фильтром TCP-портов")
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--install", action="store_true", help=argparse.SUPPRESS)
    options.add_argument("--stats", action="store_true", help="показать статистику сразу")
    options.add_argument("--all", action="store_true", help="показать все сохранённые адреса")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "Запусти команду от root или через sudo.\n")
    try:
        if args.install:
            install()
        elif args.stats or args.all or not (sys.stdin.isatty() and sys.stdout.isatty()):
            report(args.all)
        else:
            dashboard()
    except (EOFError, KeyboardInterrupt):
        print()
    except ERRORS as error:
        parser.exit(1, f"Ошибка stat_scan: {error}\n")


if __name__ == "__main__":
    main()
STAT_SCAN_MENU_PY

cat > "$stage/vps-guard-443-update.py" <<'STAT_SCAN_UPDATER_PY'
import argparse
import fcntl
import os
import re
import subprocess
import sys
import tempfile
from ipaddress import collapse_addresses, ip_address, ip_network, summarize_address_range
from pathlib import Path
from typing import NamedTuple
from urllib.request import urlopen

URL = "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt"
CONFIG = Path("/etc/vps-guard-443.nft")
TABLE = "vps_guard_443"
LOCK = "/run/vps-guard-443-update.lock"
POLICY_LINES = re.compile(r"(?m)^# stat_scan_ip (base4|base6|block|exclude) ([^\n]+)\n")
SETS = ("sources_v4", "sources_v6")
MAX_BYTES = 256 * 1024
SET_ELEMENTS = re.compile(
    r"(?m)(^[ \t]*set[ \t]+(sources_v[46])\s*\{[^{}]*?"
    r"\belements\s*=\s*\{)([^{}]*)(\})"
)


def nft(*args, data=None, capture=False):
    return subprocess.run(
        ["/usr/sbin/nft", *args], input=data, text=True, check=True,
        stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE,
    ).stdout


def download():
    with urlopen(URL, timeout=15) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Файл списка превышает 256 КиБ")

    networks = {4: [], 6: []}
    for line in data.decode("ascii").splitlines():
        value = line.strip()
        if not value:
            continue
        if "/" not in value:
            raise ValueError(f"Ожидался CIDR-префикс: {value!r}")
        net = ip_network(value, strict=True)
        if not net.is_global or net.is_multicast or net.is_reserved:
            raise ValueError(f"Некорректная публичная сеть: {net}")
        networks[net.version].append(net)

    result = {
        f"sources_v{version}": tuple(collapse_addresses(items))
        for version, items in networks.items()
    }
    for version, minimum, prefix_limit in ((4, 100, 12), (6, 4, 24)):
        prefixes = result[f"sources_v{version}"]
        if len(prefixes) < minimum or any(net.prefixlen < prefix_limit for net in prefixes):
            raise ValueError(f"Неожиданный размер или ширина списка IPv{version}")
    return result


def elements(value):
    prefixes = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        first, separator, last = item.partition("-")
        if separator:
            prefixes.extend(summarize_address_range(ip_address(first.strip()), ip_address(last.strip())))
        else:
            prefixes.append(ip_network(item, strict=True))
    return tuple(collapse_addresses(prefixes))


def set_blocks(text):
    blocks = {}
    for match in SET_ELEMENTS.finditer(text):
        name = match[2]
        if name in blocks:
            raise ValueError(f"Повторяющийся набор {name}")
        blocks[name] = match
    return blocks


def render_config(text, updates):
    def replace(match):
        name = match[2]
        if name not in updates:
            return match[0]
        rows = ",\n".join(f"            {net}" for net in updates[name])
        return f"{match[1]}\n{rows}\n        {match[4]}"

    return SET_ELEMENTS.sub(replace, text)


def set_batch(updates):
    commands = []
    for name, prefixes in updates.items():
        members = ", ".join(map(str, prefixes))
        commands.append(f"flush set inet {TABLE} {name}")
        if members:
            commands.append(f"add element inet {TABLE} {name} {{ {members} }}")
    return "\n".join(commands) + "\n"


class Policy(NamedTuple):
    base: dict
    block: set
    exclude: set


def configured_sources(text):
    blocks = set_blocks(text)
    if blocks.keys() != set(SETS):
        raise ValueError("В конфигурации ожидаются наборы sources_v4 и sources_v6")
    return {name: elements(blocks[name][3]) for name in SETS}


def read_policy(text, stored):
    values = {name: [] for name in ("base4", "base6", "block", "exclude")}
    for match in POLICY_LINES.finditer(text):
        values[match[1]].extend(match[2].split())
    if not any(values.values()):
        return Policy(stored, set(), set())
    if not values["base4"] or not values["base6"]:
        raise ValueError("В конфигурации отсутствует исходный список подсетей")
    base = {
        f"sources_v{v}": tuple(ip_network(value) for value in values[f"base{v}"])
        for v in (4, 6)
    }
    return Policy(base, set(map(ip_address, values["block"])), set(map(ip_address, values["exclude"])))


def policy_text(text, policy):
    text = POLICY_LINES.sub("", text)
    if not (policy.block or policy.exclude):
        return text
    values = {
        "base4": policy.base["sources_v4"],
        "base6": policy.base["sources_v6"],
        "block": sorted(policy.block, key=lambda ip: (ip.version, int(ip))),
        "exclude": sorted(policy.exclude, key=lambda ip: (ip.version, int(ip))),
    }
    lines = []
    for name, items in values.items():
        for start in range(0, len(items), 20):
            parts = " ".join(map(str, items[start:start + 20]))
            lines.append(f"# stat_scan_ip {name} {parts}\n")
    return "".join(lines) + text


def effective_sources(policy):
    result = {}
    for version in (4, 6):
        name = f"sources_v{version}"
        additions = [ip_network(str(ip)) for ip in policy.block if ip.version == version]
        prefixes = list(collapse_addresses([*policy.base[name], *additions]))
        for address in policy.exclude:
            if address.version != version:
                continue
            host = ip_network(str(address))
            prefixes = [
                part for net in prefixes
                for part in (net.address_exclude(host) if address in net else (net,))
            ]
        result[name] = tuple(collapse_addresses(prefixes))
    return result


def active_sources():
    if f"table inet {TABLE}" not in nft("list", "tables", capture=True).splitlines():
        return None
    active = {}
    for name in SETS:
        text = nft("-s", "list", "set", "inet", TABLE, name, capture=True)
        block = set_blocks(text).get(name)
        active[name] = elements(block[3]) if block is not None else ()
    return active


def write_config(text):
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=CONFIG.parent, prefix=".vps-guard-443.", delete=False,
    ) as output:
        candidate = Path(output.name)
        try:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
            os.replace(candidate, CONFIG)
        finally:
            candidate.unlink(missing_ok=True)


def apply_policy(original, stored, policy, check_only=False):
    wanted = effective_sources(policy)
    active = active_sources()
    saved_changes = {name: wanted[name] for name in SETS if wanted[name] != stored[name]}
    live_changes = {
        name: wanted[name] for name in SETS
        if active is not None and (check_only or wanted[name] != active[name])
    }
    updated = policy_text(render_config(original, saved_changes), policy)
    if check_only or updated != original:
        nft("-c", "-f", "-", data=updated)
    if live_changes:
        batch = set_batch(live_changes)
        nft("-c", "-f", "-", data=batch)
    if check_only:
        return False
    if live_changes:
        nft("-f", "-", data=batch)
    try:
        if updated != original:
            write_config(updated)
    except OSError:
        if live_changes:
            nft("-f", "-", data=set_batch({name: active[name] for name in live_changes}))
        raise
    return bool(live_changes) or updated != original


def change_ip(address, block):
    if "%" in address:
        raise ValueError("Введи IPv4 или IPv6 без идентификатора интерфейса")
    address = ip_address(address)
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        original = CONFIG.read_text(encoding="utf-8")
        stored = configured_sources(original)
        policy = read_policy(original, stored)
        added, excluded = (policy.block, policy.exclude) if block else (policy.exclude, policy.block)
        added.add(address)
        excluded.discard(address)
        apply_policy(original, stored, policy)
    return address


def update(check_only):
    incoming = download()
    original = CONFIG.read_text(encoding="utf-8")
    stored = configured_sources(original)
    policy = read_policy(original, stored)._replace(base=incoming)
    changed = apply_policy(original, stored, policy, check_only)
    counts = f"IPv4: {len(incoming['sources_v4'])}, IPv6: {len(incoming['sources_v6'])}"
    message = "Проверка списка и команд прошла" if check_only else "Список обновлён" if changed else "Список уже актуален"
    print(f"{message}. {counts}")
    if policy.block or policy.exclude:
        print(f"Ручные добавления: {len(policy.block)} · исключения: {len(policy.exclude)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        with open(LOCK, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            update(args.check)
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        details = (getattr(error, "stderr", None) or str(error)).strip()
        print(f"Ошибка обновления списка: {details}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
STAT_SCAN_UPDATER_PY

cat > "$stage/bootstrap.py" <<'STAT_SCAN_BOOTSTRAP_PY'
import argparse
import fcntl
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path

VERSION = "1.0.0"
BUNDLE = Path(__file__).parent
MENU_PATH = BUNDLE / "stat_scan-menu.py"
UPDATER_PATH = BUNDLE / "vps-guard-443-update.py"
menu = runpy.run_path(str(MENU_PATH))
updater = runpy.run_path(str(UPDATER_PATH))
CONFIG = menu["CONFIG"]
COMMAND = menu["COMMAND"]
UPDATER = menu["UPDATER"]
UNIT_DIR = menu["UNIT_DIR"]
GUARD = menu["GUARD"]
SERVICE = menu["SERVICE"]
TIMER = menu["TIMER"]
TABLE = menu["TABLE"]
nft = menu["nft"]
systemctl = menu["systemctl"]
write = menu["atomic_write"]

GUARD_UNIT = """[Unit]
Description=Stat Scan TCP source filter
DefaultDependencies=no
Wants=network-pre.target
After=local-fs.target nftables.service
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/vps-guard-443.nft
ExecStop=/usr/sbin/nft destroy table inet vps_guard_443

[Install]
WantedBy=multi-user.target
"""

UPDATE_UNIT = """[Unit]
Description=Refresh address sets for Stat Scan
Wants=network-online.target
After=vps-guard-443.service network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/sbin/vps-guard-443-update.py
TimeoutStartSec=90s
"""

TIMER_UNIT = """[Unit]
Description=Daily refresh of address sets for Stat Scan

[Timer]
OnCalendar=*-*-* 04:30:00 Europe/Moscow
Persistent=true

[Install]
WantedBy=timers.target
"""


def parse_ports(value):
    parts = value.split(",")
    if any(not re.fullmatch(r"[0-9]{1,5}", part) or not 1 <= int(part) <= 65535 for part in parts):
        raise argparse.ArgumentTypeError("укажи TCP-порты через запятую, например 443,37566")
    return sorted({int(part) for part in parts})


def check_environment():
    if os.geteuid() != 0:
        raise ValueError("Запусти install.sh от root или через sudo")
    missing = [
        name for name in ("/usr/bin/python3", "/usr/sbin/nft", "/usr/bin/systemctl", "/usr/bin/journalctl")
        if not os.access(name, os.X_OK)
    ]
    if missing:
        raise ValueError(
            "Отсутствуют команды " + ", ".join(missing)
            + ". На Ubuntu/Debian установи зависимости: apt-get install nftables python3 ca-certificates"
        )
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("Для установки нужен VPS с systemd")
    menu["ZoneInfo"]("Europe/Moscow")


def base_configuration(ports):
    empty = (
        f"destroy table inet {TABLE}\n"
        f"table inet {TABLE} {{\n"
        "    set sources_v4 { type ipv4_addr; flags interval; elements = { } }\n"
        "    set sources_v6 { type ipv6_addr; flags interval; elements = { } }\n"
        + menu["CHAIN"] + menu["CHAIN_POLICY"] + "    }\n}\n"
    )
    sources = updater["download"]()
    config = updater["render_config"](empty, sources)
    for port in ports:
        config = menu["config_for_port"](config, {}, port, True)
    return config


def cleanup(installed, loaded):
    if loaded:
        for args in (("disable", "--now", TIMER), ("stop", SERVICE), ("disable", "--now", GUARD)):
            result = systemctl(*args, check=False)
            if result.returncode:
                print(f"Не удалось остановить {args[-1]}. Файлы установки оставлены для восстановления.", file=sys.stderr)
                return
        nft("destroy", "table", "inet", TABLE)
    for path in reversed(installed):
        path.unlink(missing_ok=True)
    if loaded:
        systemctl("daemon-reload", check=False)


def fresh_install(ports):
    files = {
        COMMAND: (MENU_PATH.read_bytes(), 0o755),
        UPDATER: (UPDATER_PATH.read_bytes(), 0o644),
        UNIT_DIR / GUARD: (GUARD_UNIT.encode(), 0o644),
        UNIT_DIR / SERVICE: (UPDATE_UNIT.encode(), 0o644),
        UNIT_DIR / TIMER: (TIMER_UNIT.encode(), 0o644),
    }
    with open(menu["LOCK"], "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        conflicts = [str(path) for path in (CONFIG, *files) if path.exists() or path.is_symlink()]
        if conflicts:
            raise ValueError("Обнаружены файлы предыдущей установки: " + ", ".join(conflicts))
        if f"table inet {TABLE}" in nft("list", "tables").splitlines():
            raise ValueError(f"Таблица inet {TABLE} уже существует. Проверь прежнюю установку")
        config = base_configuration(ports)
        nft("-c", "-f", "-", data=config)
        files[CONFIG] = (config.encode("utf-8"), 0o600)
        installed = []
        loaded = False
        try:
            for path, (content, mode) in files.items():
                write(path, content, mode)
                installed.append(path)
            systemctl("daemon-reload")
            loaded = True
            systemctl("start", GUARD)
            systemctl("enable", GUARD)
            systemctl("enable", "--now", TIMER)
        except (OSError, subprocess.SubprocessError, KeyboardInterrupt):
            cleanup(installed, loaded)
            raise
    print(f"Stat Scan v{VERSION} установлен. TCP-порты: {', '.join(map(str, ports))}.")
    print("Автообновление: ежедневно в 04:30 по Москве.")


def upgrade(ports):
    current = sorted(menu["saved_ports"]())
    if ports is not None and current != ports:
        raise ValueError("На установленном VPS меняй порты через меню stat_scan")
    menu["install"]()
    print(f"Stat Scan v{VERSION} обновлён. TCP-порты: {', '.join(map(str, current)) or 'список пуст'}.")


def main():
    parser = argparse.ArgumentParser(description="Установка Stat Scan на Ubuntu/Debian VPS")
    parser.add_argument("--version", action="version", version=f"Stat Scan v{VERSION}")
    parser.add_argument("--ports", type=parse_ports, help="TCP-порты при первой установке, по умолчанию 443")
    args = parser.parse_args()
    try:
        check_environment()
        if CONFIG.is_file():
            upgrade(args.ports)
        else:
            fresh_install(args.ports or [443])
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        detail = (getattr(error, "stderr", None) or str(error)).strip()
        parser.exit(1, f"Ошибка установки: {detail}\n")
    except KeyboardInterrupt:
        parser.exit(130, "\nУстановка прервана.\n")
    print("Открой меню командой stat_scan.")


if __name__ == "__main__":
    main()
STAT_SCAN_BOOTSTRAP_PY

python3 "$stage/bootstrap.py" "$@"
