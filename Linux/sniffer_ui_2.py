"""
NetSniff v2.0 — Professional Network Packet Analyzer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requires:  python3 -m pip install PySide6
Run with:  sudo -E python3 netsniff_pyside6.py   (raw-socket capture needs root)
"""

import sys, os, socket, struct, time, csv, json, datetime
from dataclasses import dataclass, field
from typing import Optional, List

try:
    from PySide6.QtCore import QThread, QTimer, Qt, Signal
    from PySide6.QtGui import QAction, QColor, QFont, QPalette
    from PySide6.QtWidgets import (
        QAbstractItemView, QApplication, QCheckBox, QColorDialog, QComboBox,
        QDialog, QFileDialog, QFrame, QGridLayout, QHeaderView, QHBoxLayout,
        QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
        QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QSpinBox,
        QSplitter, QStackedWidget, QStatusBar, QTableWidget,
        QTableWidgetItem, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
    )
except ModuleNotFoundError as exc:
    if exc.name and exc.name.startswith("PySide6"):
        raise SystemExit(
            "PySide6 non è installato. Esegui:\n"
            "  python3 -m pip install --upgrade pip\n"
            "  python3 -m pip install PySide6"
        ) from exc
    raise
except ImportError as exc:
    raise SystemExit(
        "PySide6 è installato, ma manca una dipendenza di sistema di Qt.\n"
        f"Dettaglio: {exc}\n"
        "Su Debian/Ubuntu prova: sudo apt install libegl1 libgl1 libxkbcommon-x11-0"
    ) from exc


APP_NAME    = "NetSniff"
APP_VERSION = "2.0.0"
CAPTURE_IFACES = ["eth0", "wlan0", "lo", "any"]

PROTO_COLORS = {
    "TCP":  ("#0a1929", "#aad4f0"),
    "UDP":  ("#0a1f0a", "#90ee90"),
    "DNS":  ("#0d1a2a", "#87ceeb"),
    "TLS":  ("#1a0a2a", "#dda0dd"),
    "HTTP": ("#1a1500", "#ffe680"),
    "ICMP": ("#1a1000", "#ffcc80"),
    "ARP":  ("#180a2a", "#c9b1e8"),
    "IPv6": ("#001a1a", "#80ffff"),
    "DHCP": ("#0a1a0a", "#80ff80"),
}

THEMES = {
    "Dark": {
        "window":"#1e1e1e", "panel":"#2c2c2c", "panelAlt":"#252526",
        "border":"#3c3c3c", "accent":"#007acc", "accentText":"#ffffff",
        "text":"#cccccc", "textMuted":"#888888", "textDim":"#555555",
        "base":"#1e1e1e", "altBase":"#252526",
        "highlight":"#094771", "hlText":"#ffffff",
        "btn":"#3c3c3c", "btnText":"#cccccc",
        "input":"#1e1e1e", "inputBorder":"#555555",
        "filterBg":"#1e3a1e", "filterBorder":"#3a7d3a", "filterText":"#d4f4d4",
        "statusBg":"#007acc", "hexOffset":"#5a8a9f", "hexBytes":"#4ec9b0", "hexAscii":"#ce9178",
        "treeSym":"#569cd6", "treeKey":"#9cdcfe", "treeVal":"#ce9178",
    },
    "Nord": {
        "window":"#2e3440", "panel":"#3b4252", "panelAlt":"#343a45",
        "border":"#4c566a", "accent":"#88c0d0", "accentText":"#2e3440",
        "text":"#d8dee9", "textMuted":"#9099a7", "textDim":"#5a6478",
        "base":"#2e3440", "altBase":"#3b4252",
        "highlight":"#5e81ac", "hlText":"#eceff4",
        "btn":"#3b4252", "btnText":"#d8dee9",
        "input":"#2e3440", "inputBorder":"#4c566a",
        "filterBg":"#2a3545", "filterBorder":"#5e81ac", "filterText":"#d8dee9",
        "statusBg":"#5e81ac", "hexOffset":"#81a1c1", "hexBytes":"#88c0d0", "hexAscii":"#ebcb8b",
        "treeSym":"#81a1c1", "treeKey":"#88c0d0", "treeVal":"#ebcb8b",
    },
    "Monokai": {
        "window":"#272822", "panel":"#3e3d32", "panelAlt":"#333330",
        "border":"#49483e", "accent":"#a6e22e", "accentText":"#272822",
        "text":"#f8f8f2", "textMuted":"#908070", "textDim":"#595347",
        "base":"#272822", "altBase":"#3e3d32",
        "highlight":"#49483e", "hlText":"#f8f8f2",
        "btn":"#49483e", "btnText":"#f8f8f2",
        "input":"#272822", "inputBorder":"#75715e",
        "filterBg":"#2a2c1e", "filterBorder":"#a6e22e", "filterText":"#f8f8f2",
        "statusBg":"#75715e", "hexOffset":"#66d9e8", "hexBytes":"#a6e22e", "hexAscii":"#fd971f",
        "treeSym":"#66d9e8", "treeKey":"#a6e22e", "treeVal":"#fd971f",
    },
    "Solarized": {
        "window":"#002b36", "panel":"#073642", "panelAlt":"#003d4a",
        "border":"#094c5c", "accent":"#268bd2", "accentText":"#fdf6e3",
        "text":"#839496", "textMuted":"#586e75", "textDim":"#2f555f",
        "base":"#002b36", "altBase":"#073642",
        "highlight":"#1a5975", "hlText":"#fdf6e3",
        "btn":"#073642", "btnText":"#839496",
        "input":"#002b36", "inputBorder":"#2aa198",
        "filterBg":"#002f3d", "filterBorder":"#2aa198", "filterText":"#93a1a1",
        "statusBg":"#268bd2", "hexOffset":"#2aa198", "hexBytes":"#859900", "hexAscii":"#cb4b16",
        "treeSym":"#268bd2", "treeKey":"#2aa198", "treeVal":"#cb4b16",
    },
    "Dracula": {
        "window":"#282a36", "panel":"#343746", "panelAlt":"#2f3142",
        "border":"#44475a", "accent":"#bd93f9", "accentText":"#282a36",
        "text":"#f8f8f2", "textMuted":"#9496a5", "textDim":"#55576a",
        "base":"#21222c", "altBase":"#282a36",
        "highlight":"#44475a", "hlText":"#f8f8f2",
        "btn":"#44475a", "btnText":"#f8f8f2",
        "input":"#21222c", "inputBorder":"#6272a4",
        "filterBg":"#21272a", "filterBorder":"#50fa7b", "filterText":"#f8f8f2",
        "statusBg":"#6272a4", "hexOffset":"#6272a4", "hexBytes":"#8be9fd", "hexAscii":"#ffb86c",
        "treeSym":"#bd93f9", "treeKey":"#8be9fd", "treeVal":"#ffb86c",
    },
    "Light": {
        "window":"#ffffff", "panel":"#f3f3f3", "panelAlt":"#f8f8f8",
        "border":"#e1e4e8", "accent":"#0366d6", "accentText":"#ffffff",
        "text":"#24292e", "textMuted":"#586069", "textDim":"#a8b0ba",
        "base":"#ffffff", "altBase":"#f6f8fa",
        "highlight":"#dbedff", "hlText":"#24292e",
        "btn":"#eff3f6", "btnText":"#24292e",
        "input":"#ffffff", "inputBorder":"#e1e4e8",
        "filterBg":"#f0fff4", "filterBorder":"#34d058", "filterText":"#24292e",
        "statusBg":"#0366d6", "hexOffset":"#0366d6", "hexBytes":"#005cc5", "hexAscii":"#e36209",
        "treeSym":"#0366d6", "treeKey":"#005cc5", "treeVal":"#e36209",
    },
}

TCP_FLAGS = {0x001:"FIN",0x002:"SYN",0x004:"RST",0x008:"PSH",0x010:"ACK",0x020:"URG"}
IP_PROTOS = {1:"ICMP",6:"TCP",17:"UDP",41:"IPv6",58:"ICMPv6",89:"OSPF"}
WELL_KNOWN_PORTS = {
    20:"FTP-DATA",21:"FTP",22:"SSH",23:"TELNET",25:"SMTP",
    53:"DNS",67:"DHCP",68:"DHCP",80:"HTTP",110:"POP3",
    143:"IMAP",161:"SNMP",443:"HTTPS",465:"SMTPS",
    514:"SYSLOG",587:"SMTP",993:"IMAPS",995:"POP3S",
    1194:"OpenVPN",1723:"PPTP",3306:"MySQL",5432:"PostgreSQL",
    6379:"Redis",8080:"HTTP-ALT",8443:"HTTPS-ALT",
}


@dataclass
class PacketRecord:
    no: int = 0
    timestamp: float = 0.0
    captured_at: float = 0.0
    src: str = ""
    dst: str = ""
    protocol: str = ""
    length: int = 0
    info: str = ""
    raw: bytes = field(default_factory=bytes)
    src_mac: str = ""
    dst_mac: str = ""
    eth_proto: int = 0
    ip_src: str = ""
    ip_dst: str = ""
    ip_ttl: int = 0
    ip_proto: int = 0
    ip_header_len: int = 0
    ip_total_len: int = 0
    ip_flags: str = ""
    ip_id: int = 0
    ip_checksum: int = 0
    tcp_sport: int = 0
    tcp_dport: int = 0
    tcp_seq: int = 0
    tcp_ack_num: int = 0
    tcp_flags_str: str = ""
    tcp_window: int = 0
    udp_sport: int = 0
    udp_dport: int = 0
    udp_length: int = 0
    icmp_type: int = 0
    icmp_code: int = 0
    icmp_id: int = 0
    icmp_seq: int = 0
    arp_op: str = ""
    arp_sender_mac: str = ""
    arp_sender_ip: str = ""
    arp_target_mac: str = ""
    arp_target_ip: str = ""
    marked: bool = False
    ref_time: bool = False

def _mac(b: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in b)

def _port_name(port: int) -> str:
    return f"{port} ({WELL_KNOWN_PORTS[port]})" if port in WELL_KNOWN_PORTS else str(port)

def _flags(raw: int) -> str:
    return ', '.join(n for m,n in TCP_FLAGS.items() if raw & m) or "—"

def _ip_flags(off_flags: int) -> str:
    parts = []
    if off_flags & 0x4000: parts.append("DF")
    if off_flags & 0x2000: parts.append("MF")
    return f"0x{off_flags>>13:01x} ({', '.join(parts) or 'none'})"

def parse_packet(no: int, raw: bytes, t0: float) -> PacketRecord:
    now = time.time()
    p = PacketRecord(no=no, timestamp=now-t0, captured_at=now, length=len(raw), raw=raw)
    if len(raw) < 14:
        p.protocol, p.info = "RAW", f"Truncated frame ({len(raw)} bytes)"
        p.src = p.dst = "—"
        return p

    p.dst_mac = _mac(raw[0:6])
    p.src_mac = _mac(raw[6:12])
    p.eth_proto = struct.unpack('!H', raw[12:14])[0]

    if p.eth_proto == 0x0800:
        _parse_ipv4(p, raw[14:])
    elif p.eth_proto == 0x0806:
        _parse_arp(p, raw[14:])
    elif p.eth_proto == 0x86DD:
        p.protocol = "IPv6"
        p.src, p.dst = p.src_mac, p.dst_mac
        p.info = "IPv6 packet"
    else:
        p.protocol = f"0x{p.eth_proto:04x}"
        p.src, p.dst = p.src_mac, p.dst_mac
        p.info = "Unknown Ethernet protocol"

    return p

def _parse_ipv4(p: PacketRecord, data: bytes):
    if len(data) < 20:
        p.protocol, p.info = "IP", "Truncated IP header"
        return
    ihl = (data[0] & 0x0f) * 4
    if ihl < 20 or ihl > len(data):
        p.protocol, p.info = "IP", "Invalid or truncated IP header"
        return
    p.ip_header_len  = ihl
    p.ip_total_len   = struct.unpack('!H', data[2:4])[0]
    p.ip_id          = struct.unpack('!H', data[4:6])[0]
    off_flags        = struct.unpack('!H', data[6:8])[0]
    p.ip_flags       = _ip_flags(off_flags)
    p.ip_ttl         = data[8]
    p.ip_proto       = data[9]
    p.ip_checksum    = struct.unpack('!H', data[10:12])[0]
    p.ip_src         = socket.inet_ntoa(data[12:16])
    p.ip_dst         = socket.inet_ntoa(data[16:20])
    p.src, p.dst     = p.ip_src, p.ip_dst

    payload = data[ihl:]
    if   p.ip_proto == 6:   _parse_tcp(p, payload)
    elif p.ip_proto == 17:  _parse_udp(p, payload)
    elif p.ip_proto == 1:   _parse_icmp(p, payload)
    else:
        proto_name = IP_PROTOS.get(p.ip_proto, f"IP/{p.ip_proto}")
        p.protocol = proto_name
        p.info = f"{proto_name} packet"

def _parse_tcp(p: PacketRecord, data: bytes):
    if len(data) < 20:
        p.protocol, p.info = "TCP", "Truncated TCP segment"
        return
    p.tcp_sport    = struct.unpack('!H', data[0:2])[0]
    p.tcp_dport    = struct.unpack('!H', data[2:4])[0]
    p.tcp_seq      = struct.unpack('!I', data[4:8])[0]
    p.tcp_ack_num  = struct.unpack('!I', data[8:12])[0]
    offset         = (data[12] >> 4) * 4
    if offset < 20 or offset > len(data):
        p.protocol, p.info = "TCP", "Invalid or truncated TCP header"
        return
    raw_flags      = struct.unpack('!H', data[12:14])[0] & 0x1ff
    p.tcp_flags_str = _flags(raw_flags)
    p.tcp_window   = struct.unpack('!H', data[14:16])[0]

    sport, dport = p.tcp_sport, p.tcp_dport
    payload = data[offset:]

    if dport == 443 or sport == 443:
        if len(payload) > 0 and payload[0] in (0x16, 0x14, 0x15, 0x17):
            p.protocol = "TLS"
            rec_type = {0x16:"Handshake",0x14:"ChangeCipherSpec",0x15:"Alert",0x17:"AppData"}.get(payload[0],"TLS")
            p.info = f"{rec_type}: {p.ip_src}:{sport} → {p.ip_dst}:{dport}"
            return
    if dport == 80 or sport == 80:
        if payload[:4] in (b'GET ', b'POST', b'HTTP', b'HEAD', b'PUT ', b'DELE'):
            p.protocol = "HTTP"
            try:
                first_line = payload.split(b'\r\n')[0].decode('ascii','ignore')
                p.info = f"{first_line}"
            except Exception:
                p.info = "HTTP"
            return

    flags_abbr = p.tcp_flags_str.replace(" ","")
    p.protocol = "TCP"
    p.info = (f"{_port_name(sport)} → {_port_name(dport)} [{flags_abbr}] "
              f"Seq={p.tcp_seq} Win={p.tcp_window} Len={len(payload)}")

def _parse_udp(p: PacketRecord, data: bytes):
    if len(data) < 8:
        p.protocol, p.info = "UDP", "Truncated UDP datagram"
        return
    p.udp_sport  = struct.unpack('!H', data[0:2])[0]
    p.udp_dport  = struct.unpack('!H', data[2:4])[0]
    p.udp_length = struct.unpack('!H', data[4:6])[0]
    sport, dport = p.udp_sport, p.udp_dport
    payload = data[8:]

    if dport == 53 or sport == 53:
        p.protocol = "DNS"
        try:
            txid = struct.unpack('!H', payload[0:2])[0]
            flags = struct.unpack('!H', payload[2:4])[0]
            is_response = bool(flags & 0x8000)
            p.info = (f"Standard query response 0x{txid:04x}" if is_response
                      else f"Standard query 0x{txid:04x}")
        except Exception:
            p.info = "DNS"
        return

    if dport in (67, 68) or sport in (67, 68):
        p.protocol = "DHCP"
        p.info = "DHCP Discover/Offer/Request/Ack"
        return

    p.protocol = "UDP"
    p.info = f"{_port_name(sport)} → {_port_name(dport)} Len={p.udp_length}"

def _parse_icmp(p: PacketRecord, data: bytes):
    if len(data) < 4:
        p.protocol, p.info = "ICMP", "Truncated ICMP"
        return
    p.icmp_type = data[0]
    p.icmp_code = data[1]
    ICMP_TYPES = {0:"Echo (ping) reply",3:"Destination unreachable",8:"Echo (ping) request",
                  11:"Time-to-live exceeded",30:"Traceroute"}
    type_name = ICMP_TYPES.get(p.icmp_type, f"Type {p.icmp_type}")
    if p.icmp_type in (0, 8) and len(data) >= 8:
        p.icmp_id  = struct.unpack('!H', data[4:6])[0]
        p.icmp_seq = struct.unpack('!H', data[6:8])[0]
        p.info = f"{type_name}  id=0x{p.icmp_id:04x}, seq={p.icmp_seq}, ttl={p.ip_ttl}"
    else:
        p.info = f"{type_name} code={p.icmp_code}"
    p.protocol = "ICMP"

def _parse_arp(p: PacketRecord, data: bytes):
    if len(data) < 28:
        p.protocol, p.info = "ARP", "Truncated ARP"
        p.src = p.src_mac
        p.dst = p.dst_mac
        return
    op = struct.unpack('!H', data[6:8])[0]
    p.arp_sender_mac = _mac(data[8:14])
    p.arp_sender_ip  = socket.inet_ntoa(data[14:18])
    p.arp_target_mac = _mac(data[18:24])
    p.arp_target_ip  = socket.inet_ntoa(data[24:28])
    p.arp_op  = "request" if op == 1 else "reply"
    p.src, p.dst = p.arp_sender_ip, p.arp_target_ip
    p.protocol = "ARP"
    if op == 1:
        p.info = f"Who has {p.arp_target_ip}? Tell {p.arp_sender_ip}"
    else:
        p.info = f"{p.arp_sender_ip} is at {p.arp_sender_mac}"

def build_detail_tree(p: PacketRecord) -> list:
    """Return nested list of (section_label, [(key, value), ...]) tuples."""
    sections = []
    ts = datetime.datetime.fromtimestamp(p.captured_at or time.time()).strftime("%b %d, %Y %H:%M:%S.%f")
    sections.append((
        f"Frame {p.no}: {p.length} bytes on wire, {p.length} bytes captured",
        [("Frame Number", str(p.no)),
         ("Arrival Time", ts),
         ("Frame Length", f"{p.length} bytes ({p.length*8} bits)"),
         ("Capture Length", f"{p.length} bytes"),
         ("Protocols in frame", "eth:ip:" + p.protocol.lower())]
    ))

    if p.eth_proto:
        sections.append((
            f"Ethernet II,  Src: {p.src_mac},  Dst: {p.dst_mac}",
            [("Destination", p.dst_mac),
             ("Source", p.src_mac),
             ("Type", f"{'IPv4' if p.eth_proto==0x800 else 'ARP' if p.eth_proto==0x806 else 'IPv6' if p.eth_proto==0x86DD else hex(p.eth_proto)} (0x{p.eth_proto:04x})")]
        ))

    if p.ip_src:
        sections.append((
            f"Internet Protocol Version 4,  Src: {p.ip_src},  Dst: {p.ip_dst}",
            [("Version", "4"),
             ("Header Length", f"{p.ip_header_len} bytes"),
             ("Total Length", str(p.ip_total_len)),
             ("Identification", f"0x{p.ip_id:04x} ({p.ip_id})"),
             ("Flags", p.ip_flags),
             ("Time to Live", str(p.ip_ttl)),
             ("Protocol", f"{IP_PROTOS.get(p.ip_proto, str(p.ip_proto))} ({p.ip_proto})"),
             ("Header Checksum", f"0x{p.ip_checksum:04x}"),
             ("Source Address", p.ip_src),
             ("Destination Address", p.ip_dst)]
        ))

    if p.tcp_sport:
        sections.append((
            f"Transmission Control Protocol,  Src Port: {p.tcp_sport},  Dst Port: {p.tcp_dport},  Seq: {p.tcp_seq}",
            [("Source Port", _port_name(p.tcp_sport)),
             ("Destination Port", _port_name(p.tcp_dport)),
             ("Sequence Number", str(p.tcp_seq)),
             ("Acknowledgment Number", str(p.tcp_ack_num)),
             ("Flags", p.tcp_flags_str),
             ("Window", str(p.tcp_window))]
        ))
    elif p.udp_sport:
        sections.append((
            f"User Datagram Protocol,  Src Port: {p.udp_sport},  Dst Port: {p.udp_dport}",
            [("Source Port", _port_name(p.udp_sport)),
             ("Destination Port", _port_name(p.udp_dport)),
             ("Length", str(p.udp_length))]
        ))
    elif p.icmp_type is not None and p.protocol == "ICMP":
        items = [("Type", str(p.icmp_type)),("Code", str(p.icmp_code))]
        if p.icmp_id: items += [("Identifier", f"0x{p.icmp_id:04x}"),("Sequence Number", str(p.icmp_seq))]
        sections.append(("Internet Control Message Protocol", items))
    elif p.arp_op:
        sections.append((
            f"Address Resolution Protocol ({p.arp_op})",
            [("Opcode", p.arp_op),
             ("Sender MAC", p.arp_sender_mac), ("Sender IP", p.arp_sender_ip),
             ("Target MAC", p.arp_target_mac), ("Target IP", p.arp_target_ip)]
        ))
    return sections

def hex_dump(raw: bytes) -> list:
    """Return list of (offset, hex_str, ascii_str) for each 16-byte line."""
    lines = []
    for i in range(0, len(raw), 16):
        chunk = raw[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        if len(chunk) > 8:
            hex_part = hex_part[:23] + '  ' + hex_part[23:]
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append((f"{i:04x}", hex_part.ljust(49), ascii_part))
    return lines


class CaptureThread(QThread):
    packet_received = Signal(object)
    error_occurred  = Signal(str)
    stats_updated   = Signal(int, float)

    def __init__(self, interface="eth0", snap_len=65535):
        super().__init__()
        self.interface  = interface
        self.snap_len   = max(64, min(int(snap_len), 65535))
        self._stop_flag = False
        self._count     = 0
        self._t0        = time.time()
        self._last_tick = self._t0
        self._last_count = 0

    def run(self):
        self._stop_flag = False
        self._t0        = time.time()
        self._last_tick = self._t0
        self._count     = 0
        self._last_count = 0
        if not hasattr(socket, "AF_PACKET"):
            self.error_occurred.emit("La cattura raw è supportata solo su Linux.")
            return
        try:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            if self.interface != "any":
                conn.bind((self.interface, 0))
            conn.settimeout(0.1)
        except PermissionError:
            self.error_occurred.emit(
                "Permission denied — run as root or grant CAP_NET_RAW:\n"
                "  sudo -E python3 netsniff_pyside6.py"
            )
            return
        except OSError as e:
            self.error_occurred.emit(f"Cannot open interface '{self.interface}': {e}")
            return

        try:
            while not self._stop_flag:
                try:
                    raw, _ = conn.recvfrom(self.snap_len)
                except socket.timeout:
                    continue
                self._count += 1
                pkt = parse_packet(self._count, raw, self._t0)
                self.packet_received.emit(pkt)
                now = time.time()
                if now - self._last_tick >= 1.0:
                    pps = (self._count - self._last_count) / (now - self._last_tick)
                    self.stats_updated.emit(self._count, pps)
                    self._last_tick, self._last_count = now, self._count
        finally:
            conn.close()

    def stop(self):
        self._stop_flag = True


def packet_matches(p: PacketRecord, expr: str) -> bool:
    if not expr.strip():
        return True
    expr = expr.strip().lower()
    if expr in ("tcp","udp","dns","http","https","tls","icmp","arp","ipv6","dhcp"):
        return p.protocol.lower() == expr or (expr=="https" and p.protocol.lower()=="tls")
    if "ip.addr==" in expr.replace(" ",""):
        ip = expr.replace(" ","").split("ip.addr==")[1].strip()
        return ip in (p.ip_src, p.ip_dst)
    if "ip.src==" in expr.replace(" ",""):
        ip = expr.replace(" ","").split("ip.src==")[1].strip()
        return p.ip_src == ip
    if "ip.dst==" in expr.replace(" ",""):
        ip = expr.replace(" ","").split("ip.dst==")[1].strip()
        return p.ip_dst == ip
    if "tcp.port==" in expr.replace(" ",""):
        try:
            port = int(expr.replace(" ","").split("tcp.port==")[1])
            return p.tcp_sport == port or p.tcp_dport == port
        except ValueError:
            pass
    if "udp.port==" in expr.replace(" ",""):
        try:
            port = int(expr.replace(" ","").split("udp.port==")[1])
            return p.udp_sport == port or p.udp_dport == port
        except ValueError:
            pass
    if "frame.len>" in expr.replace(" ",""):
        try:
            n = int(expr.replace(" ","").split("frame.len>")[1])
            return p.length > n
        except ValueError:
            pass
    if "frame.len<" in expr.replace(" ",""):
        try:
            n = int(expr.replace(" ","").split("frame.len<")[1])
            return p.length < n
        except ValueError:
            pass
    fields = [p.src, p.dst, p.protocol, p.info, p.src_mac, p.dst_mac]
    return any(expr in f.lower() for f in fields)


class SettingsDialog(QDialog):
    def __init__(self, main_win):
        super().__init__(main_win)
        self.main_win = main_win
        self.setWindowTitle("Preferences")
        self.resize(960, 700)
        self._build_ui()
        self._load_values()

    def _build_ui(self):
        t = self.main_win.theme
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0,0,0,0)
        outer.setSpacing(0)

        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(210)
        self.sidebar.setStyleSheet(f"""
            QListWidget {{ background:{t['panel']}; border:none; outline:none; font-size:12pt; }}
            QListWidget::item {{ color:{t['textMuted']}; padding:10px 16px; border-left:3px solid transparent; }}
            QListWidget::item:selected {{ background:{t['accent']}22; color:{t['accent']}; border-left:3px solid {t['accent']}; }}
        """)
        SECTIONS = [("🎨","Appearance"),("⊞","Layout"),("📡","Capture"),("⊟","Columns"),
                    ("🖌","Protocol Colors"),("🕐","Timestamps"),("🔎","Name Resolution"),
                    ("⧉","Saved Filters"),("⬇","Export"),("⚡","Performance"),
                    ("🔔","Notifications"),("⌨","Shortcuts")]
        for icon, label in SECTIONS:
            item = QListWidgetItem(f"  {icon}  {label}")
            self.sidebar.addItem(item)
        self.sidebar.currentRowChanged.connect(self._switch_page)
        outer.addWidget(self.sidebar)

        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0,0,0,0)
        right_layout.setSpacing(0)

        self.stack = QStackedWidget()
        right_layout.addWidget(self.stack)

        footer = QWidget()
        footer.setFixedHeight(56)
        footer.setStyleSheet(f"background:{t['panel']};border-top:1px solid {t['border']};")
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(16,8,16,8)
        fl.addStretch()
        cancel_btn = QPushButton("Cancel"); cancel_btn.clicked.connect(self.reject)
        apply_btn  = QPushButton("Apply");  apply_btn.clicked.connect(self._apply)
        ok_btn     = QPushButton("OK");     ok_btn.clicked.connect(self._ok)
        for b in (cancel_btn, apply_btn, ok_btn):
            b.setFixedWidth(100)
            b.setFixedHeight(32)
            b.setStyleSheet(f"QPushButton{{background:{t['btn']};color:{t['btnText']};border:1px solid {t['border']};border-radius:4px;font-size:11pt;padding:6px 14px;}}"
                            f"QPushButton:hover{{background:{t['border']};}} QPushButton:pressed{{background:{t['highlight']};}}")
            fl.addWidget(b)
        right_layout.addWidget(footer)

        right_widget = QWidget()
        right_widget.setLayout(right_layout)
        right_widget.setStyleSheet(f"background:{t['panelAlt']};")
        outer.addWidget(right_widget)

        self._add_pages()
        self.sidebar.setCurrentRow(0)

    def _add_pages(self):
        t = self.main_win.theme
        mw = self.main_win

        def page():
            w = QWidget(); w.setStyleSheet(f"background:{t['panelAlt']};"); return w
        def label(txt, muted=False):
            l = QLabel(txt); l.setStyleSheet(f"color:{'#888' if muted else t['text']};font-size:12pt;"); return l
        def combo(opts, current=""):
            c = QComboBox(); c.addItems(opts)
            if current in opts: c.setCurrentText(current)
            c.setStyleSheet(f"QComboBox{{background:{t['input']};color:{t['text']};border:1px solid {t['inputBorder']};padding:6px 12px;border-radius:4px;min-width:160px;font-size:12pt;}}"
                            f"QComboBox QAbstractItemView{{background:{t['input']};color:{t['text']};selection-background-color:{t['highlight']};font-size:12pt;}}")
            return c
        def toggle(checked=False):
            cb = QCheckBox(); cb.setChecked(checked)
            cb.setStyleSheet(f"QCheckBox::indicator{{width:22px;height:22px;border-radius:11px;border:2px solid {t['border']};}}"
                             f"QCheckBox::indicator:checked{{background:{t['accent']};border:2px solid {t['accent']};}}")
            return cb
        def spin(val, mn, mx, step=1):
            s = QSpinBox(); s.setRange(mn,mx); s.setValue(val); s.setSingleStep(step)
            s.setStyleSheet(f"QSpinBox{{background:{t['input']};color:{t['text']};border:1px solid {t['inputBorder']};padding:6px 8px;border-radius:4px;min-width:90px;font-size:12pt;}}")
            return s
        def row_item(lbl_text, sub_text, ctrl):
            row = QWidget(); rl = QHBoxLayout(row); rl.setContentsMargins(0,10,0,10)
            left = QVBoxLayout(); left.setSpacing(3); left.addWidget(label(lbl_text))
            if sub_text: left.addWidget(label(sub_text, muted=True))
            rl.addLayout(left); rl.addStretch(); rl.addWidget(ctrl)
            row.setStyleSheet(f"border-bottom:1px solid {t['border']}44;")
            return row
        def section_label(txt):
            l = QLabel(txt); l.setStyleSheet(f"color:{t['accent']};font-size:10pt;font-weight:bold;letter-spacing:1px;text-transform:uppercase;margin-top:16px;margin-bottom:4px;")
            return l

        p0 = page(); p0l = QVBoxLayout(p0); p0l.setContentsMargins(16,8,16,8)
        p0l.addWidget(section_label("Theme"))
        theme_grid = QWidget(); tg = QGridLayout(theme_grid); tg.setSpacing(6)
        self._theme_btns = {}
        for i, (name, td) in enumerate(THEMES.items()):
            btn = QPushButton(name); btn.setCheckable(True); btn.setFixedHeight(64)
            btn.setStyleSheet(f"QPushButton{{background:{td['window']};color:{td['text']};border:2px solid {td['border']};border-radius:6px;font-size:12pt;font-weight:bold;}}"
                             f"QPushButton:checked{{border:2px solid {td['accent']};}}")
            btn.clicked.connect(lambda _,n=name: self._select_theme(n))
            self._theme_btns[name] = btn
            tg.addWidget(btn, i//3, i%3)
        p0l.addWidget(theme_grid)
        p0l.addWidget(section_label("Typography"))
        self._font_family = combo(["monospace","Fira Code","JetBrains Mono","Courier New","Consolas"], mw.settings.get("fontFamily","monospace"))
        self._font_size   = spin(mw.settings.get("fontSize",10), 7, 18)
        p0l.addWidget(row_item("Font family", "Applies to packet list and hex dump", self._font_family))
        p0l.addWidget(row_item("Font size", "Row font size in points", self._font_size))
        p0l.addWidget(section_label("Rows"))
        self._row_height  = combo(["compact","normal","comfortable"], mw.settings.get("rowHeight","compact"))
        self._alt_rows    = toggle(mw.settings.get("altRows",False))
        p0l.addWidget(row_item("Row height", "Affects how many packets are visible at once", self._row_height))
        p0l.addWidget(row_item("Alternating row colors", "Slight tint on every other row", self._alt_rows))
        p0l.addStretch()
        self.stack.addWidget(p0)

        p1 = page(); p1l = QVBoxLayout(p1); p1l.setContentsMargins(16,8,16,8)
        p1l.addWidget(section_label("Panel Layout"))
        self._layout_btns = {}
        for lname, ldesc in [("3-pane","Packet list + Detail tree + Hex dump"),
                              ("detail-only","Packet list + Detail tree"),
                              ("hex-only","Packet list + Hex dump"),
                              ("list-only","Packet list only")]:
            rb = QRadioButton(f"  {lname}   — {ldesc}")
            rb.setStyleSheet(f"color:{t['text']};font-size:12pt;")
            rb.setChecked(mw.settings.get("layout","3-pane") == lname)
            self._layout_btns[lname] = rb
            p1l.addWidget(rb)
        p1l.addWidget(section_label("Panels"))
        self._show_toolbar    = toggle(mw.settings.get("showToolbar",True))
        self._show_filterbar  = toggle(mw.settings.get("showFilterBar",True))
        self._show_statusbar  = toggle(mw.settings.get("showStatusBar",True))
        p1l.addWidget(row_item("Show main toolbar","",self._show_toolbar))
        p1l.addWidget(row_item("Show filter bar","",self._show_filterbar))
        p1l.addWidget(row_item("Show status bar","",self._show_statusbar))
        p1l.addStretch()
        self.stack.addWidget(p1)

        p2 = page(); p2l = QVBoxLayout(p2); p2l.setContentsMargins(16,8,16,8)
        p2l.addWidget(section_label("Interface"))
        self._interface   = combo(mw._interfaces(), mw.settings.get("interface", "any"))
        self._promiscuous = toggle(mw.settings.get("promiscuous",True))
        self._monitor     = toggle(mw.settings.get("monitorMode",False))
        p2l.addWidget(row_item("Default interface","",self._interface))
        p2l.addWidget(row_item("Promiscuous mode","Capture all packets, not just addressed to this host",self._promiscuous))
        p2l.addWidget(row_item("Monitor mode","802.11 management frames — Wi-Fi only",self._monitor))
        p2l.addWidget(section_label("Limits"))
        self._snap_len    = spin(mw.settings.get("snapLen",65535),64,65535,64)
        self._max_packets = spin(mw.settings.get("maxPackets",10000),100,100000,100)
        self._autoscroll  = toggle(mw.settings.get("autoScroll",True))
        self._confirm_clear = toggle(mw.settings.get("confirmClear",True))
        p2l.addWidget(row_item("Snapshot length (bytes)","Max bytes captured per packet (65535 = full)",self._snap_len))
        p2l.addWidget(row_item("Max packets to keep","Older packets discarded when limit is reached",self._max_packets))
        p2l.addWidget(row_item("Auto-scroll during capture","Scroll to newest packet automatically",self._autoscroll))
        p2l.addWidget(row_item("Confirm before clearing","Show dialog before clearing the packet list",self._confirm_clear))
        p2l.addStretch()
        self.stack.addWidget(p2)

        p3 = page(); p3l = QVBoxLayout(p3); p3l.setContentsMargins(16,8,16,8)
        p3l.addWidget(section_label("Visible Columns"))
        self._col_checks = {}
        for col_id, col_label in [("no","No."),("time","Time"),("src","Source"),("dst","Destination"),
                                    ("proto","Protocol"),("len","Length"),("info","Info")]:
            cb = toggle(mw.settings.get("cols",{}).get(col_id,True))
            self._col_checks[col_id] = cb
            p3l.addWidget(row_item(col_label, f"Column key: {col_id}", cb))
        p3l.addStretch()
        self.stack.addWidget(p3)

        p4 = page(); p4l = QVBoxLayout(p4); p4l.setContentsMargins(16,8,16,8)
        p4l.addWidget(section_label("Protocol Row Colors"))
        p4l.addWidget(label("Click a swatch to open the color picker. Changes apply immediately.", muted=True))
        self._proto_color_btns = {}
        for proto, (bg, fg) in PROTO_COLORS.items():
            bg_btn = QPushButton("  BG  "); bg_btn.setFixedSize(64,30)
            fg_btn = QPushButton("  FG  "); fg_btn.setFixedSize(64,30)
            actual_bg = mw.settings.get("protoColors",{}).get(proto,{}).get("bg", bg)
            actual_fg = mw.settings.get("protoColors",{}).get(proto,{}).get("fg", fg)
            bg_btn.setStyleSheet(f"background:{actual_bg};color:white;border:none;border-radius:4px;font-size:10pt;font-weight:bold;")
            fg_btn.setStyleSheet(f"background:{actual_fg};color:black;border:none;border-radius:4px;font-size:10pt;font-weight:bold;")
            bg_btn.clicked.connect(lambda _,p=proto,b=bg_btn,side="bg": self._pick_proto_color(p,b,side))
            fg_btn.clicked.connect(lambda _,p=proto,b=fg_btn,side="fg": self._pick_proto_color(p,b,side))
            self._proto_color_btns[proto] = (bg_btn, fg_btn)
            badge = QLabel(proto); badge.setFixedWidth(54); badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setStyleSheet(f"background:{actual_bg};color:{actual_fg};border-radius:3px;padding:4px 8px;font-size:11pt;font-weight:bold;")
            row = QWidget(); rl = QHBoxLayout(row); rl.setContentsMargins(0,4,0,4)
            rl.addWidget(badge); rl.addWidget(label(proto)); rl.addStretch()
            rl.addWidget(QLabel("BG")); rl.addWidget(bg_btn); rl.addWidget(QLabel("FG")); rl.addWidget(fg_btn)
            row.setStyleSheet(f"border-bottom:1px solid {t['border']}44;")
            p4l.addWidget(row)
        p4l.addStretch()
        self.stack.addWidget(p4)

        p5 = page(); p5l = QVBoxLayout(p5); p5l.setContentsMargins(16,8,16,8)
        p5l.addWidget(section_label("Display Format"))
        self._ts_btns = {}
        formats = [("Relative","0.013210"),("Absolute","Jul 13, 2026 09:14:33.013210"),
                   ("Delta from previous","0.000727"),("UTC","2026-07-13T09:14:33.013210Z"),
                   ("Epoch (seconds)","1752398073.013210")]
        for fmt, example in formats:
            rb = QRadioButton(f"  {fmt}")
            rb.setStyleSheet(f"color:{t['text']};font-size:12pt;"); rb.setToolTip(f"Example: {example}")
            rb.setChecked(mw.settings.get("timestampFmt","Relative")==fmt)
            self._ts_btns[fmt] = rb; p5l.addWidget(rb)
        p5l.addWidget(section_label("Precision"))
        self._ts_prec = spin(mw.settings.get("timestampPrec",6),0,9)
        p5l.addWidget(row_item("Decimal places","",self._ts_prec))
        p5l.addStretch()
        self.stack.addWidget(p5)

        p6 = page(); p6l = QVBoxLayout(p6); p6l.setContentsMargins(16,8,16,8)
        p6l.addWidget(section_label("Resolution"))
        self._res_mac    = toggle(mw.settings.get("resolveMAC",False))
        self._res_ip     = toggle(mw.settings.get("resolveIP",False))
        self._res_ports  = toggle(mw.settings.get("resolvePorts",True))
        p6l.addWidget(row_item("Resolve MAC addresses","Convert hardware addresses to vendor names",self._res_mac))
        p6l.addWidget(row_item("Resolve network (DNS) addresses","Reverse-DNS lookup for IP addresses",self._res_ip))
        p6l.addWidget(row_item("Resolve transport names","Port numbers → service names (443→https)",self._res_ports))
        p6l.addWidget(section_label("DNS"))
        self._dns_conc = spin(mw.settings.get("dnsConcurrent",20),1,100)
        p6l.addWidget(row_item("Concurrent DNS requests","Max parallel reverse-DNS lookups",self._dns_conc))
        p6l.addStretch()
        self.stack.addWidget(p6)

        p7 = page(); p7l = QVBoxLayout(p7); p7l.setContentsMargins(16,8,16,8)
        p7l.addWidget(section_label("Saved Display Filters"))
        self._filters_list = QListWidget()
        self._filters_list.setStyleSheet(f"background:{t['input']};color:{t['text']};border:1px solid {t['border']};border-radius:4px;font-size:12pt;")
        self._filters_list.setFixedHeight(140)
        for f in mw.settings.get("savedFilters",[]):
            self._filters_list.addItem(f"{f['name']}  —  {f['filter']}")
        p7l.addWidget(self._filters_list)
        del_btn = QPushButton("Remove selected")
        del_btn.setStyleSheet(f"QPushButton{{background:{t['input']};color:{t['textMuted']};border:1px solid {t['border']};padding:4px 12px;border-radius:3px;}}")
        del_btn.clicked.connect(lambda: self._filters_list.takeItem(self._filters_list.currentRow()))
        p7l.addWidget(del_btn)
        p7l.addWidget(section_label("Add New Filter"))
        self._new_filter_name = QLineEdit(); self._new_filter_name.setPlaceholderText("Filter name")
        self._new_filter_expr = QLineEdit(); self._new_filter_expr.setPlaceholderText("e.g. tcp.port==443")
        add_btn = QPushButton("Add Filter")
        for w in (self._new_filter_name, self._new_filter_expr):
            w.setStyleSheet(f"QLineEdit{{background:{t['input']};color:{t['text']};border:1px solid {t['inputBorder']};padding:7px 10px;border-radius:4px;font-size:12pt;}}")
            p7l.addWidget(w)
        add_btn.setStyleSheet(f"QPushButton{{background:{t['accent']};color:{t['accentText']};border:none;padding:8px 18px;border-radius:4px;font-size:12pt;font-weight:bold;}}")
        add_btn.clicked.connect(self._add_filter)
        p7l.addWidget(add_btn)
        p7l.addStretch()
        self.stack.addWidget(p7)

        p8 = page(); p8l = QVBoxLayout(p8); p8l.setContentsMargins(16,8,16,8)
        p8l.addWidget(section_label("Default Export Format"))
        self._export_fmt_btns = {}
        for fmt, desc in [("csv","CSV — comma-separated, opens in Excel"),
                           ("json","JSON — machine-readable, all fields"),
                           ("txt","Plain text — human-readable summary")]:
            rb = QRadioButton(f"  {fmt.upper()}  —  {desc}")
            rb.setStyleSheet(f"color:{t['text']};font-size:12pt;")
            rb.setChecked(mw.settings.get("exportFmt","csv")==fmt)
            self._export_fmt_btns[fmt] = rb; p8l.addWidget(rb)
        p8l.addWidget(section_label("CSV Options"))
        self._export_sep = combo([",",";","\\t","|"], mw.settings.get("exportSep",","))
        self._export_headers = toggle(mw.settings.get("exportHeaders",True))
        p8l.addWidget(row_item("Field separator","",self._export_sep))
        p8l.addWidget(row_item("Include column headers","",self._export_headers))
        p8l.addStretch()
        self.stack.addWidget(p8)

        p9 = page(); p9l = QVBoxLayout(p9); p9l.setContentsMargins(16,8,16,8)
        p9l.addWidget(section_label("Rendering"))
        self._update_interval = spin(mw.settings.get("updateInterval",100),16,2000,50)
        p9l.addWidget(row_item("UI update interval (ms)","Lower = smoother, higher = less CPU",self._update_interval))
        p9l.addWidget(section_label("Memory"))
        self._buf_size = spin(mw.settings.get("bufferSize",2),1,512)
        p9l.addWidget(row_item("Capture buffer size (MB)","Ring buffer per interface",self._buf_size))
        p9l.addStretch()
        self.stack.addWidget(p9)

        p10 = page(); p10l = QVBoxLayout(p10); p10l.setContentsMargins(16,8,16,8)
        p10l.addWidget(section_label("Protocol Alerts"))
        self._notify_checks = {}
        for proto in PROTO_COLORS:
            cb = toggle(mw.settings.get("notifyProtos",{}).get(proto,False))
            self._notify_checks[proto] = cb
            p10l.addWidget(row_item(f"Alert on {proto} packet","",cb))
        p10l.addWidget(section_label("Expert Info"))
        self._notify_retrans = toggle(True)
        self._notify_rst     = toggle(True)
        p10l.addWidget(row_item("Alert on TCP retransmission","",self._notify_retrans))
        p10l.addWidget(row_item("Alert on TCP reset (RST)","",self._notify_rst))
        p10l.addStretch()
        self.stack.addWidget(p10)

        p11 = page(); p11l = QVBoxLayout(p11); p11l.setContentsMargins(16,8,16,8)
        p11l.addWidget(section_label("Keyboard Shortcuts"))
        tbl = QTableWidget(0, 2); tbl.setHorizontalHeaderLabels(["Action","Shortcut"])
        tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setStyleSheet(f"QTableWidget{{background:{t['input']};color:{t['text']};border:1px solid {t['border']};gridline-color:{t['border']};font-size:12pt;}}"
                          f"QHeaderView::section{{background:{t['panel']};color:{t['textMuted']};border:none;padding:8px;font-size:11pt;}}")
        tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        shortcuts = [("Start/Stop Capture","Ctrl+E"),("Restart","Ctrl+R"),("Find Packet","Ctrl+F"),
                     ("Go to Packet","Ctrl+G"),("First Packet","Ctrl+Home"),("Last Packet","Ctrl+End"),
                     ("Previous Packet","↑"),("Next Packet","↓"),("Zoom In","Ctrl++"),
                     ("Zoom Out","Ctrl+-"),("Reset Zoom","Ctrl+0"),("Mark Packet","Ctrl+M"),
                     ("Copy as Text","Ctrl+C"),("Export","Ctrl+Shift+S"),("Statistics","Ctrl+Shift+I"),
                     ("Open Settings","Ctrl+,"),("About","F1")]
        for action, key in shortcuts:
            r = tbl.rowCount(); tbl.insertRow(r)
            tbl.setItem(r, 0, QTableWidgetItem(action))
            ki = QTableWidgetItem(key); ki.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter); tbl.setItem(r, 1, ki)
        p11l.addWidget(tbl)
        self.stack.addWidget(p11)

    def _switch_page(self, idx):
        self.stack.setCurrentIndex(idx)

    def _select_theme(self, name):
        for n, b in self._theme_btns.items(): b.setChecked(n == name)
        self.main_win._set_theme(name)

    def _pick_proto_color(self, proto, btn, side):
        color = QColorDialog.getColor(QColor(btn.palette().button().color()), self)
        if color.isValid():
            hex_c = color.name()
            if side == "bg":
                btn.setStyleSheet(f"background:{hex_c};color:white;border:none;border-radius:3px;font-size:10pt;")
                self.main_win.settings.setdefault("protoColors",{}).setdefault(proto,{})["bg"] = hex_c
            else:
                btn.setStyleSheet(f"background:{hex_c};color:black;border:none;border-radius:3px;font-size:10pt;")
                self.main_win.settings.setdefault("protoColors",{}).setdefault(proto,{})["fg"] = hex_c

    def _add_filter(self):
        name = self._new_filter_name.text().strip()
        expr = self._new_filter_expr.text().strip()
        if name and expr:
            self._filters_list.addItem(f"{name}  —  {expr}")
            self._new_filter_name.clear(); self._new_filter_expr.clear()

    def _load_values(self):
        mw = self.main_win
        cur = mw.settings.get("themeName","Dark")
        for n, b in self._theme_btns.items(): b.setChecked(n == cur)

    def _apply(self):
        mw = self.main_win
        mw.settings["fontFamily"]    = self._font_family.currentText()
        mw.settings["fontSize"]      = self._font_size.value()
        mw.settings["rowHeight"]     = self._row_height.currentText()
        mw.settings["altRows"]       = self._alt_rows.isChecked()
        mw.settings["layout"]        = next((k for k,v in self._layout_btns.items() if v.isChecked()), "3-pane")
        mw.settings["showToolbar"]   = self._show_toolbar.isChecked()
        mw.settings["showFilterBar"] = self._show_filterbar.isChecked()
        mw.settings["showStatusBar"] = self._show_statusbar.isChecked()
        mw.settings["interface"]     = self._interface.currentText()
        mw.settings["promiscuous"]   = self._promiscuous.isChecked()
        mw.settings["monitorMode"]   = self._monitor.isChecked()
        mw.settings["snapLen"]       = self._snap_len.value()
        mw.settings["maxPackets"]    = self._max_packets.value()
        mw.settings["autoScroll"]    = self._autoscroll.isChecked()
        mw.settings["confirmClear"]  = self._confirm_clear.isChecked()
        mw.settings["cols"]          = {k: v.isChecked() for k, v in self._col_checks.items()}
        mw.settings["timestampFmt"]  = next((k for k,v in self._ts_btns.items() if v.isChecked()), "Relative")
        mw.settings["timestampPrec"] = self._ts_prec.value()
        mw.settings["resolveMAC"]    = self._res_mac.isChecked()
        mw.settings["resolveIP"]     = self._res_ip.isChecked()
        mw.settings["resolvePorts"]  = self._res_ports.isChecked()
        mw.settings["dnsConcurrent"] = self._dns_conc.value()
        mw.settings["exportFmt"]     = next((k for k,v in self._export_fmt_btns.items() if v.isChecked()), "csv")
        mw.settings["exportSep"]     = self._export_sep.currentText()
        mw.settings["exportHeaders"] = self._export_headers.isChecked()
        mw.settings["updateInterval"]= self._update_interval.value()
        mw.settings["bufferSize"]    = self._buf_size.value()
        mw.settings["notifyProtos"]  = {k: v.isChecked() for k, v in self._notify_checks.items()}
        mw.settings["savedFilters"]  = []
        for i in range(self._filters_list.count()):
            txt = self._filters_list.item(i).text()
            parts = txt.split("  —  ", 1)
            if len(parts) == 2:
                mw.settings["savedFilters"].append({"name":parts[0].strip(),"filter":parts[1].strip()})
        mw._apply_settings()

    def _ok(self):
        self._apply(); self.accept()


class StatsDialog(QDialog):
    def __init__(self, packets: List[PacketRecord], parent=None):
        super().__init__(parent)
        t = parent.theme if parent is not None else THEMES["Dark"]
        self.setWindowTitle("Statistics — Protocol Hierarchy")
        self.resize(560, 420)
        self.setStyleSheet(f"background:{t['panelAlt']};color:{t['text']};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16,16,16,16)

        total = len(packets)
        total_bytes = sum(p.length for p in packets)
        counts: dict = {}
        for p in packets:
            counts[p.protocol] = counts.get(p.protocol, 0) + 1

        summary = QHBoxLayout()
        for k, v in [("Total Packets", str(total)), ("Total Bytes", f"{total_bytes:,}"), ("Protocols", str(len(counts)))]:
            box = QFrame(); box.setStyleSheet(f"background:{t['input']};border:1px solid {t['border']};border-radius:4px;")
            bl = QVBoxLayout(box); bl.setContentsMargins(12,8,12,8)
            vl = QLabel(str(v)); vl.setStyleSheet(f"color:{t['accent']};font-size:16pt;font-weight:bold;")
            kl = QLabel(k); kl.setStyleSheet(f"color:{t['textMuted']};font-size:10pt;")
            vl.setAlignment(Qt.AlignmentFlag.AlignCenter); kl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            bl.addWidget(vl); bl.addWidget(kl); summary.addWidget(box)
        layout.addLayout(summary)

        tbl = QTableWidget(0, 4)
        tbl.setHorizontalHeaderLabels(["Protocol","Packets","Bytes","% of total"])
        tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setStyleSheet(f"QTableWidget{{background:{t['input']};color:{t['text']};border:1px solid {t['border']};gridline-color:{t['border']}44;font-size:11pt;}}"
                          f"QHeaderView::section{{background:{t['panel']};color:{t['textMuted']};border:none;padding:7px;}}")
        tbl.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        tbl.verticalHeader().setVisible(False)
        for proto, cnt in sorted(counts.items(), key=lambda x:-x[1]):
            r = tbl.rowCount(); tbl.insertRow(r)
            proto_bytes = sum(p.length for p in packets if p.protocol==proto)
            pct = (cnt/total*100) if total else 0
            colors = PROTO_COLORS.get(proto, ("#333","#ccc"))
            pi = QTableWidgetItem(proto)
            pi.setBackground(QColor(colors[0])); pi.setForeground(QColor(colors[1]))
            pi.setFont(QFont("", -1, QFont.Weight.Bold))
            tbl.setItem(r,0,pi)
            for col, val in enumerate([str(cnt), f"{proto_bytes:,}", f"{pct:.1f}%"], 1):
                item = QTableWidgetItem(val); item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                tbl.setItem(r, col, item)
        layout.addWidget(tbl)

        close_btn = QPushButton("Close"); close_btn.clicked.connect(self.accept)
        close_btn.setStyleSheet(f"QPushButton{{background:{t['accent']};color:{t['accentText']};border:none;padding:6px 20px;border-radius:3px;}}")
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)


class MainWindow(QMainWindow):
    COLUMNS = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
    COLUMN_KEYS = ("no", "time", "src", "dst", "proto", "len", "info")

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION} — Network Packet Analyzer")
        self.resize(1440, 900)
        self.packets: List[PacketRecord] = []
        self.filtered: List[PacketRecord] = []
        self.capture_thread: Optional[CaptureThread] = None
        self._t0 = time.time()
        self._pps = 0.0
        self._ref_time: Optional[float] = None
        self._col_resized_once = False

        self.settings = {
            "themeName": "Dark", "fontSize": 10, "fontFamily": "monospace",
            "rowHeight": "normal", "altRows": False, "showToolbar": True,
            "showFilterBar": True, "showStatusBar": True, "layout": "3-pane",
            "interface": self._default_interface(), "promiscuous": True,
            "monitorMode": False, "snapLen": 65535, "maxPackets": 10000,
            "autoScroll": True, "confirmClear": True,
            "timestampFmt": "Relative", "timestampPrec": 6,
            "resolveMAC": False, "resolveIP": False, "resolvePorts": True,
            "exportFmt": "csv", "exportSep": ",", "exportHeaders": True,
            "updateInterval": 100, "bufferSize": 2,
            "cols": {key: True for key in self.COLUMN_KEYS},
            "savedFilters": [
                {"name": "HTTP only", "filter": "http"},
                {"name": "DNS queries", "filter": "dns"},
                {"name": "Large packets", "filter": "frame.len>500"},
            ],
            "protoColors": {},
            "notifyProtos": {proto: False for proto in PROTO_COLORS},
        }
        self.theme = THEMES[self.settings["themeName"]]
        self._build_ui()
        self._apply_settings()

    @staticmethod
    def _interfaces() -> List[str]:
        try:
            names = [name for _, name in socket.if_nameindex()]
        except OSError:
            names = []
        return names + (["any"] if "any" not in names else [])

    @classmethod
    def _default_interface(cls) -> str:
        names = cls._interfaces()
        return next((name for name in names if name not in ("lo", "any")), names[0] if names else "any")

    def _build_ui(self):
        self._build_menu()

        central = QWidget(self)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.toolbar_widget = QWidget()
        toolbar_layout = QHBoxLayout(self.toolbar_widget)
        toolbar_layout.setContentsMargins(10, 7, 10, 7)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self._interfaces())
        self.interface_combo.setCurrentText(self.settings["interface"])
        toolbar_layout.addWidget(QLabel("Interface:"))
        toolbar_layout.addWidget(self.interface_combo)
        self.start_button = QPushButton("▶ Start")
        self.stop_button = QPushButton("■ Stop")
        self.clear_button = QPushButton("Clear")
        self.export_button = QPushButton("Export")
        self.settings_button = QPushButton("Preferences")
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_packets)
        self.export_button.clicked.connect(self.export_packets)
        self.settings_button.clicked.connect(self.open_settings)
        for button in (self.start_button, self.stop_button, self.clear_button,
                       self.export_button, self.settings_button):
            toolbar_layout.addWidget(button)
        toolbar_layout.addStretch()
        outer.addWidget(self.toolbar_widget)

        self.filter_widget = QWidget()
        filter_layout = QHBoxLayout(self.filter_widget)
        filter_layout.setContentsMargins(10, 6, 10, 6)
        filter_layout.addWidget(QLabel("Display filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("tcp, dns, ip.addr==192.168.1.10, tcp.port==443, frame.len>500")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_edit)
        outer.addWidget(self.filter_widget)

        self.packet_table = QTableWidget(0, len(self.COLUMNS))
        self.packet_table.setHorizontalHeaderLabels(self.COLUMNS)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.packet_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.packet_table.setAlternatingRowColors(False)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.itemSelectionChanged.connect(self._show_selected_packet)

        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabels(["Field", "Value"])
        self.detail_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.detail_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        self.bottom_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.bottom_splitter.addWidget(self.detail_tree)
        self.bottom_splitter.addWidget(self.hex_view)
        self.bottom_splitter.setSizes([700, 700])
        self.main_splitter = QSplitter(Qt.Orientation.Vertical)
        self.main_splitter.addWidget(self.packet_table)
        self.main_splitter.addWidget(self.bottom_splitter)
        self.main_splitter.setSizes([520, 300])
        outer.addWidget(self.main_splitter, 1)
        self.setCentralWidget(central)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self._update_status()
        self.stop_button.setEnabled(False)

    def _build_menu(self):
        file_menu = self.menuBar().addMenu("File")
        capture_menu = self.menuBar().addMenu("Capture")
        tools_menu = self.menuBar().addMenu("Tools")
        help_menu = self.menuBar().addMenu("Help")

        def action(menu, text, slot, shortcut=None):
            item = QAction(text, self)
            if shortcut:
                item.setShortcut(shortcut)
            item.triggered.connect(slot)
            menu.addAction(item)
            return item

        action(file_menu, "Export…", self.export_packets, "Ctrl+Shift+S")
        action(file_menu, "Exit", self.close, "Ctrl+Q")
        action(capture_menu, "Start", self.start_capture, "Ctrl+E")
        action(capture_menu, "Stop", self.stop_capture, "Ctrl+R")
        action(capture_menu, "Clear", self.clear_packets, "Ctrl+L")
        action(tools_menu, "Statistics", self.show_statistics, "Ctrl+Shift+I")
        action(tools_menu, "Preferences", self.open_settings, "Ctrl+,")
        action(help_menu, "About", self.show_about, "F1")

    def showEvent(self, event):
        super().showEvent(event)
        if not self._col_resized_once:
            self._col_resized_once = True
            QTimer.singleShot(0, self._fit_columns)

    def _fit_columns(self):
        header = self.packet_table.horizontalHeader()
        header.resizeSections(QHeaderView.ResizeMode.ResizeToContents)
        for index in range(6):
            header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

    def start_capture(self):
        if self.capture_thread and self.capture_thread.isRunning():
            return
        interface = self.interface_combo.currentText() or "any"
        self.settings["interface"] = interface
        self._t0 = time.time()
        self.capture_thread = CaptureThread(interface, self.settings["snapLen"])
        self.capture_thread.packet_received.connect(self._on_packet)
        self.capture_thread.stats_updated.connect(self._on_stats)
        self.capture_thread.error_occurred.connect(self._capture_error)
        self.capture_thread.finished.connect(self._capture_finished)
        self.capture_thread.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.interface_combo.setEnabled(False)
        self.status_bar.showMessage(f"Capturing on {interface}…")

    def stop_capture(self):
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            if not self.capture_thread.wait(1500):
                self.status_bar.showMessage("Waiting for capture thread to stop…")
                return
        self._capture_finished()

    def _capture_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.interface_combo.setEnabled(True)
        self._update_status()

    def _capture_error(self, message: str):
        QMessageBox.critical(self, "Capture error", message)
        self._capture_finished()

    def _on_packet(self, packet: PacketRecord):
        self.packets.append(packet)
        max_packets = self.settings["maxPackets"]
        overflow = len(self.packets) - max_packets
        if overflow > 0:
            del self.packets[:overflow]
            self.apply_filter()
        elif packet_matches(packet, self.filter_edit.text()):
            self.filtered.append(packet)
            self._append_packet_row(packet)
        self._update_status()

    def _append_packet_row(self, packet: PacketRecord):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        values = (
            str(packet.no), self._format_time(packet), packet.src, packet.dst,
            packet.protocol, str(packet.length), packet.info,
        )
        colors = self.settings.get("protoColors", {}).get(packet.protocol, {})
        default_bg, default_fg = PROTO_COLORS.get(packet.protocol, (None, None))
        bg, fg = colors.get("bg", default_bg), colors.get("fg", default_fg)
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column in (0, 1, 5):
                item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if bg:
                item.setBackground(QColor(bg))
            if fg:
                item.setForeground(QColor(fg))
            self.packet_table.setItem(row, column, item)
        if self.settings["autoScroll"]:
            self.packet_table.scrollToBottom()

    def _format_time(self, packet: PacketRecord) -> str:
        precision = self.settings["timestampPrec"]
        mode = self.settings["timestampFmt"]
        if mode == "Absolute":
            base = datetime.datetime.fromtimestamp(packet.captured_at).strftime("%H:%M:%S")
            fraction = f"{datetime.datetime.fromtimestamp(packet.captured_at).microsecond:06d}".ljust(precision, "0")
            return base if precision == 0 else f"{base}.{fraction[:precision]}"
        if mode == "UTC":
            dt = datetime.datetime.fromtimestamp(packet.captured_at, datetime.timezone.utc)
            return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")
        if mode == "Epoch (seconds)":
            return f"{packet.captured_at:.{precision}f}"
        if mode == "Delta from previous":
            try:
                index = self.packets.index(packet)
                delta = packet.timestamp - self.packets[index - 1].timestamp if index else 0.0
            except ValueError:
                delta = 0.0
            return f"{delta:.{precision}f}"
        return f"{packet.timestamp:.{precision}f}"

    def apply_filter(self, _text=None):
        expression = self.filter_edit.text()
        self.filtered = [packet for packet in self.packets if packet_matches(packet, expression)]
        self.packet_table.setUpdatesEnabled(False)
        self.packet_table.setRowCount(0)
        for packet in self.filtered:
            self._append_packet_row(packet)
        self.packet_table.setUpdatesEnabled(True)
        self._update_status()

    def _show_selected_packet(self):
        row = self.packet_table.currentRow()
        if row < 0 or row >= len(self.filtered):
            return
        packet = self.filtered[row]
        self.detail_tree.clear()
        for section, fields in build_detail_tree(packet):
            parent = QTreeWidgetItem([section, ""])
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            for key, value in fields:
                parent.addChild(QTreeWidgetItem([key, value]))
            self.detail_tree.addTopLevelItem(parent)
            parent.setExpanded(True)
        lines = [f"{offset}  {hex_bytes}  {ascii_text}" for offset, hex_bytes, ascii_text in hex_dump(packet.raw)]
        self.hex_view.setPlainText("\n".join(lines))

    def clear_packets(self):
        if self.packets and self.settings["confirmClear"]:
            answer = QMessageBox.question(
                self, "Clear packets", "Remove all captured packets?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.packets.clear()
        self.filtered.clear()
        self.packet_table.setRowCount(0)
        self.detail_tree.clear()
        self.hex_view.clear()
        self._update_status()

    @staticmethod
    def _packet_dict(packet: PacketRecord) -> dict:
        return {
            "no": packet.no, "timestamp": packet.timestamp,
            "captured_at": packet.captured_at, "source": packet.src,
            "destination": packet.dst, "protocol": packet.protocol,
            "length": packet.length, "info": packet.info,
            "raw_hex": packet.raw.hex(),
        }

    def export_packets(self):
        fmt = self.settings["exportFmt"]
        filters = {
            "csv": "CSV files (*.csv)", "json": "JSON files (*.json)",
            "txt": "Text files (*.txt)",
        }
        path, _ = QFileDialog.getSaveFileName(self, "Export packets", f"packets.{fmt}", filters[fmt])
        if not path:
            return
        try:
            if fmt == "json":
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump([self._packet_dict(p) for p in self.filtered], handle, indent=2)
            elif fmt == "txt":
                with open(path, "w", encoding="utf-8") as handle:
                    for p in self.filtered:
                        handle.write(f"{p.no}\t{self._format_time(p)}\t{p.src}\t{p.dst}\t{p.protocol}\t{p.length}\t{p.info}\n")
            else:
                separator = "\t" if self.settings["exportSep"] == "\\t" else self.settings["exportSep"]
                with open(path, "w", newline="", encoding="utf-8") as handle:
                    writer = csv.writer(handle, delimiter=separator)
                    if self.settings["exportHeaders"]:
                        writer.writerow(self.COLUMNS)
                    for p in self.filtered:
                        writer.writerow([p.no, self._format_time(p), p.src, p.dst, p.protocol, p.length, p.info])
        except OSError as exc:
            QMessageBox.critical(self, "Export error", str(exc))
            return
        self.status_bar.showMessage(f"Exported {len(self.filtered)} packets to {path}", 5000)

    def show_statistics(self):
        StatsDialog(self.filtered, self).exec()

    def open_settings(self):
        SettingsDialog(self).exec()

    def show_about(self):
        QMessageBox.about(
            self, f"About {APP_NAME}",
            f"<b>{APP_NAME} {APP_VERSION}</b><br>Packet analyzer built with Python and PySide6/Qt 6.<br>"
            "Raw packet capture requires Linux and root or CAP_NET_RAW.",
        )

    def _on_stats(self, count: int, pps: float):
        self._pps = pps
        self._update_status(count)

    def _update_status(self, captured_count=None):
        count = len(self.packets) if captured_count is None else captured_count
        self.status_bar.showMessage(
            f"Packets: {count}    Displayed: {len(self.filtered)}    Rate: {self._pps:.1f} pkt/s"
        )

    def _apply_settings(self):
        self.theme = THEMES.get(self.settings["themeName"], THEMES["Dark"])
        self.toolbar_widget.setVisible(self.settings["showToolbar"])
        self.filter_widget.setVisible(self.settings["showFilterBar"])
        self.status_bar.setVisible(self.settings["showStatusBar"])
        self.interface_combo.setCurrentText(self.settings["interface"])
        layout = self.settings["layout"]
        self.detail_tree.setVisible(layout in ("3-pane", "detail-only"))
        self.hex_view.setVisible(layout in ("3-pane", "hex-only"))
        self.bottom_splitter.setVisible(layout != "list-only")
        for index, key in enumerate(self.COLUMN_KEYS):
            self.packet_table.setColumnHidden(index, not self.settings["cols"].get(key, True))
        self.packet_table.setAlternatingRowColors(self.settings["altRows"])
        heights = {"compact": 20, "normal": 26, "comfortable": 34}
        self.packet_table.verticalHeader().setDefaultSectionSize(heights.get(self.settings["rowHeight"], 26))
        font = QFont(self.settings["fontFamily"], self.settings["fontSize"])
        self.packet_table.setFont(font)
        self.hex_view.setFont(font)
        self._apply_theme_palette()
        self._update_stylesheet()
        self.apply_filter()

    def _set_theme(self, name: str):
        self.settings["themeName"] = name
        self.theme = THEMES.get(name, THEMES["Dark"])
        self._apply_theme_palette()
        self._update_stylesheet()

    def _apply_theme_palette(self):
        t = self.theme
        palette = QPalette()
        role = QPalette.ColorRole
        for palette_role, key in (
            (role.Window, "window"), (role.WindowText, "text"),
            (role.Base, "base"), (role.AlternateBase, "altBase"),
            (role.ToolTipBase, "panel"), (role.ToolTipText, "text"),
            (role.Text, "text"), (role.Button, "btn"),
            (role.ButtonText, "btnText"), (role.Highlight, "highlight"),
            (role.HighlightedText, "hlText"),
        ):
            palette.setColor(palette_role, QColor(t[key]))
        QApplication.setPalette(palette)

    def _update_stylesheet(self):
        t = self.theme
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{ background: {t['window']}; color: {t['text']}; }}
            QTableWidget, QTreeWidget, QPlainTextEdit, QLineEdit, QComboBox {{
                background: {t['base']}; color: {t['text']}; border: 1px solid {t['border']};
                selection-background-color: {t['highlight']}; selection-color: {t['hlText']};
            }}
            QHeaderView::section {{ background: {t['panel']}; color: {t['textMuted']};
                border: 0; border-right: 1px solid {t['border']}; padding: 6px; }}
            QPushButton {{ background: {t['btn']}; color: {t['btnText']};
                border: 1px solid {t['border']}; border-radius: 4px; padding: 6px 12px; }}
            QPushButton:hover {{ border-color: {t['accent']}; }}
            QPushButton:disabled {{ color: {t['textDim']}; }}
            QStatusBar {{ background: {t['statusBg']}; color: white; }}
            QMenuBar, QMenu {{ background: {t['panel']}; color: {t['text']}; }}
            QMenu::item:selected {{ background: {t['highlight']}; }}
        """)

    def closeEvent(self, event):
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            if not self.capture_thread.wait(2000):
                event.ignore()
                QMessageBox.warning(self, "Capture active", "Wait for the capture thread to stop, then close again.")
                return
        event.accept()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())