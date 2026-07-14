from __future__ import annotations

import queue
import socket
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from tkinter import messagebox, ttk


PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


@dataclass(frozen=True)
class Packet:
    number: int
    timestamp: str
    source: str
    destination: str
    protocol: str
    length: int
    source_mac: str
    destination_mac: str
    ether_type: str
    ttl: str = "-"
    header_length: str = "-"
    payload: str = ""


def mac_address(raw: bytes) -> str:
    return raw.hex(":").upper()


def parse_packet(raw: bytes, number: int) -> Packet:
    """Converte un frame Ethernet in un record visualizzabile."""
    if len(raw) < 14:
        raise ValueError("Frame Ethernet troppo corto")

    destination_mac = mac_address(raw[0:6])
    source_mac = mac_address(raw[6:12])
    ether_type_number = int.from_bytes(raw[12:14], "big")
    ether_type = f"0x{ether_type_number:04X}"
    source = source_mac
    destination = destination_mac
    protocol = "Ethernet"
    ttl = "-"
    header_length = "-"
    payload = raw[14:]

    if ether_type_number == 0x0800 and len(raw) >= 34:
        ip_data = raw[14:]
        version = ip_data[0] >> 4
        ihl = (ip_data[0] & 0x0F) * 4
        if version == 4 and ihl >= 20 and len(ip_data) >= ihl:
            protocol_number = ip_data[9]
            protocol = PROTOCOLS.get(protocol_number, f"IPv4 ({protocol_number})")
            source = socket.inet_ntoa(ip_data[12:16])
            destination = socket.inet_ntoa(ip_data[16:20])
            ttl = str(ip_data[8])
            header_length = f"{ihl} byte"
            payload = ip_data[ihl:]
    elif ether_type_number == 0x0806:
        protocol = "ARP"
    elif ether_type_number == 0x86DD:
        protocol = "IPv6"

    return Packet(
        number=number,
        timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
        source=source,
        destination=destination,
        protocol=protocol,
        length=len(raw),
        source_mac=source_mac,
        destination_mac=destination_mac,
        ether_type=ether_type,
        ttl=ttl,
        header_length=header_length,
        payload=payload.hex(" ").upper(),
    )


class PacketSnifferApp(tk.Tk):
    POLL_INTERVAL_MS = 100

    def __init__(self) -> None:
        super().__init__()
        self.title("Packet Sniffer")
        self.geometry("1120x700")
        self.minsize(880, 560)

        self.packet_queue: queue.Queue[Packet | tuple[str, str]] = queue.Queue()
        self.stop_event = threading.Event()
        self.capture_thread: threading.Thread | None = None
        self.packets: list[Packet] = []
        self.packet_by_row: dict[str, Packet] = {}

        self.filter_var = tk.StringVar(value="Tutti")
        self.status_var = tk.StringVar(value="Pronto")
        self.counter_var = tk.StringVar(value="0 pacchetti")

        self._configure_style()
        self._build_interface()
        self.after(self.POLL_INTERVAL_MS, self._process_queue)
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("TkDefaultFont", 18, "bold"))
        style.configure("Status.TLabel", padding=(8, 4))
        style.configure("Treeview", rowheight=27)
        style.configure("Treeview.Heading", font=("TkDefaultFont", 10, "bold"))

    def _build_interface(self) -> None:
        header = ttk.Frame(self, padding=(18, 14, 18, 8))
        header.pack(fill="x")
        ttk.Label(header, text="Packet Sniffer", style="Title.TLabel").pack(side="left")
        ttk.Label(
            header,
            text="Cattura e analisi dei frame di rete",
            foreground="#5f6b7a",
        ).pack(side="left", padx=(14, 0), pady=(7, 0))

        controls = ttk.Frame(self, padding=(18, 6, 18, 10))
        controls.pack(fill="x")
        self.start_button = ttk.Button(controls, text="▶  Avvia", command=self.start_capture)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(
            controls, text="■  Arresta", command=self.stop_capture, state="disabled"
        )
        self.stop_button.pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Pulisci", command=self.clear_packets).pack(
            side="left", padx=(8, 20)
        )

        ttk.Label(controls, text="Protocollo:").pack(side="left")
        protocol_filter = ttk.Combobox(
            controls,
            textvariable=self.filter_var,
            values=("Tutti", "TCP", "UDP", "ICMP", "ARP", "IPv4", "IPv6", "Ethernet"),
            state="readonly",
            width=12,
        )
        protocol_filter.pack(side="left", padx=(6, 0))
        protocol_filter.bind("<<ComboboxSelected>>", lambda _event: self.refresh_table())
        ttk.Label(controls, textvariable=self.counter_var).pack(side="right")

        content = ttk.Panedwindow(self, orient="vertical")
        content.pack(fill="both", expand=True, padx=18, pady=(0, 10))

        table_frame = ttk.Frame(content)
        columns = ("number", "time", "source", "destination", "protocol", "length")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "number": ("#", 55, "center"),
            "time": ("Ora", 115, "center"),
            "source": ("Origine", 225, "w"),
            "destination": ("Destinazione", 225, "w"),
            "protocol": ("Protocollo", 110, "center"),
            "length": ("Byte", 80, "e"),
        }
        for column, (title, width, anchor) in headings.items():
            self.table.heading(column, text=title)
            self.table.column(column, width=width, minwidth=50, anchor=anchor)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.table.bind("<<TreeviewSelect>>", self._show_selected_packet)
        content.add(table_frame, weight=3)

        details_frame = ttk.LabelFrame(content, text="Dettagli pacchetto", padding=10)
        self.details = tk.Text(
            details_frame,
            height=9,
            wrap="word",
            state="disabled",
            font=("TkFixedFont", 10),
            relief="flat",
            padx=8,
            pady=8,
        )
        details_scrollbar = ttk.Scrollbar(details_frame, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=details_scrollbar.set)
        self.details.pack(side="left", fill="both", expand=True)
        details_scrollbar.pack(side="right", fill="y")
        content.add(details_frame, weight=2)

        status_bar = ttk.Frame(self, padding=(10, 2))
        status_bar.pack(fill="x", side="bottom")
        self.status_dot = tk.Canvas(status_bar, width=12, height=12, highlightthickness=0)
        self.status_dot.create_oval(2, 2, 10, 10, fill="#8492a6", outline="", tags="dot")
        self.status_dot.pack(side="left", padx=(4, 2))
        ttk.Label(status_bar, textvariable=self.status_var, style="Status.TLabel").pack(side="left")

    def start_capture(self) -> None:
        if self.capture_thread and self.capture_thread.is_alive():
            return
        self.stop_event.clear()
        self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.capture_thread.start()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_var.set("Cattura in corso…")
        self.status_dot.itemconfigure("dot", fill="#20a464")

    def stop_capture(self) -> None:
        self.stop_event.set()
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_var.set("Cattura arrestata")
        self.status_dot.itemconfigure("dot", fill="#8492a6")

    def _capture_packets(self) -> None:
        try:
            capture_socket = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
            )
            capture_socket.settimeout(0.5)
        except PermissionError:
            self.packet_queue.put(
                ("error", "Permessi insufficienti. Avvia il programma con sudo.")
            )
            return
        except (AttributeError, OSError) as exc:
            self.packet_queue.put(
                ("error", f"La cattura raw richiede Linux e un'interfaccia di rete valida.\n\n{exc}")
            )
            return

        try:
            while not self.stop_event.is_set():
                try:
                    raw_data, _address = capture_socket.recvfrom(65535)
                except socket.timeout:
                    continue
                try:
                    packet = parse_packet(raw_data, len(self.packets) + self.packet_queue.qsize() + 1)
                    self.packet_queue.put(packet)
                except ValueError:
                    continue
        finally:
            capture_socket.close()

    def _process_queue(self) -> None:
        while True:
            try:
                item = self.packet_queue.get_nowait()
            except queue.Empty:
                break

            if isinstance(item, tuple):
                _kind, message = item
                self.stop_capture()
                messagebox.showerror("Impossibile avviare la cattura", message)
            else:
                self.packets.append(item)
                if self._matches_filter(item):
                    self._insert_packet(item)
                self.counter_var.set(f"{len(self.packets)} pacchetti")
        self.after(self.POLL_INTERVAL_MS, self._process_queue)

    def _matches_filter(self, packet: Packet) -> bool:
        selected = self.filter_var.get()
        if selected == "Tutti":
            return True
        if selected == "IPv4":
            return packet.ether_type == "0x0800"
        return packet.protocol == selected

    def _insert_packet(self, packet: Packet) -> None:
        row = self.table.insert(
            "",
            "end",
            values=(
                packet.number,
                packet.timestamp,
                packet.source,
                packet.destination,
                packet.protocol,
                packet.length,
            ),
        )
        self.packet_by_row[row] = packet
        self.table.yview_moveto(1)

    def refresh_table(self) -> None:
        self.table.delete(*self.table.get_children())
        self.packet_by_row.clear()
        for packet in self.packets:
            if self._matches_filter(packet):
                self._insert_packet(packet)

    def clear_packets(self) -> None:
        self.packets.clear()
        self.packet_by_row.clear()
        self.table.delete(*self.table.get_children())
        self._set_details("")
        self.counter_var.set("0 pacchetti")

    def _show_selected_packet(self, _event: tk.Event) -> None:
        selected_rows = self.table.selection()
        if not selected_rows:
            return
        packet = self.packet_by_row[selected_rows[0]]
        payload_preview = packet.payload[:1200]
        if len(packet.payload) > len(payload_preview):
            payload_preview += " …"
        text = (
            f"Pacchetto #{packet.number}  •  {packet.timestamp}\n"
            f"Protocollo: {packet.protocol}    Lunghezza: {packet.length} byte\n"
            f"MAC origine: {packet.source_mac}\n"
            f"MAC destinazione: {packet.destination_mac}\n"
            f"EtherType: {packet.ether_type}\n"
            f"IP origine: {packet.source}\n"
            f"IP destinazione: {packet.destination}\n"
            f"TTL: {packet.ttl}    Header IP: {packet.header_length}\n\n"
            f"Payload (hex):\n{payload_preview or '—'}"
        )
        self._set_details(text)

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _close(self) -> None:
        self.stop_event.set()
        time.sleep(0.05)
        self.destroy()


if __name__ == "__main__":
    PacketSnifferApp().mainloop()
