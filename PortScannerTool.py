import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

import customtkinter as ctk
import tkinter as tk
from PIL import ImageTk
from tkinter import filedialog, messagebox

try:  # optional dependency
    from scapy.all import IP, TCP, sr1, conf  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:  # noqa: BLE001
    SCAPY_AVAILABLE = False

from session_state import describe_scope, get_target, is_url_in_scope, set_target
from ui_utils import open_image

DEFAULT_PORTS = "1-1024,1433,1521,3306,3389,5432,5900,8080"
REQUEST_TIMEOUT = 1.5


def _parse_ports(raw: str) -> List[int]:
    ports: List[int] = []
    for chunk in raw.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            start, end = chunk.split('-', 1)
            try:
                start_port = int(start)
                end_port = int(end)
            except ValueError:
                continue
            for port in range(start_port, end_port + 1):
                if 1 <= port <= 65535:
                    ports.append(port)
        else:
            try:
                port = int(chunk)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.append(port)
    return sorted(set(ports))


def _syn_scan(host: str, port: int) -> bool:
    if not SCAPY_AVAILABLE:
        return False
    conf.verb = 0
    pkt = IP(dst=host) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=REQUEST_TIMEOUT)
    if resp is None:
        return False
    if resp.haslayer(TCP) and resp.getlayer(TCP).flags & 0x12:  # SYN-ACK
        return True
    return False


def _connect_scan(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(REQUEST_TIMEOUT)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False


@dataclass
class ScanResult:
    host: str
    open_ports: Dict[int, str]


def port_scanner_tool() -> None:
    window = ctk.CTkToplevel()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    window.geometry("1100x780")
    window.title("TCP Port / SYN Scanner")

    background_image = open_image("dark.png")
    background_image = background_image.resize((window.winfo_screenwidth(), window.winfo_screenheight()))
    background_photo = ImageTk.PhotoImage(background_image)
    bg_label = tk.Label(window, image=background_photo)
    bg_label.image = background_photo
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    header = ctk.CTkLabel(window, text="Fast TCP scanner with SYN support", font=("Segoe UI", 22, "bold"))
    header.pack(pady=12)

    scope_label = ctk.CTkLabel(window, text=describe_scope())
    scope_label.pack(pady=(0, 10))

    control = ctk.CTkFrame(window)
    control.pack(fill="x", padx=30, pady=10)

    host_box = ctk.CTkTextbox(control, width=400, height=120)
    host_box.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
    control.grid_columnconfigure(0, weight=1)
    control.grid_columnconfigure(1, weight=1)

    if get_target():
        host_box.insert("1.0", get_target())

    def load_hosts() -> None:
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt")])
        if not path:
            return
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            hosts = [line.strip() for line in handle if line.strip()]
        host_box.delete("1.0", tk.END)
        host_box.insert("1.0", "\n".join(hosts))

    load_button = ctk.CTkButton(control, text="Load Hosts", command=load_hosts)
    load_button.grid(row=0, column=1, padx=10, pady=10)

    ports_label = ctk.CTkLabel(control, text="Ports (e.g. 1-1024,3306)")
    ports_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
    ports_var = tk.StringVar(value=DEFAULT_PORTS)
    ports_entry = ctk.CTkEntry(control, textvariable=ports_var)
    ports_entry.grid(row=1, column=1, padx=10, pady=5, sticky="we")

    thread_label = ctk.CTkLabel(control, text="Threads")
    thread_label.grid(row=1, column=2, padx=10, pady=5, sticky="w")
    thread_var = tk.IntVar(value=50)
    thread_entry = ctk.CTkEntry(control, width=70, textvariable=thread_var)
    thread_entry.grid(row=1, column=3, padx=10, pady=5, sticky="e")

    mode_label = ctk.CTkLabel(control, text="Mode")
    mode_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
    mode_var = tk.StringVar(value="syn" if SCAPY_AVAILABLE else "connect")
    mode_selector = ctk.CTkSegmentedButton(control, values=["syn", "connect"], variable=mode_var)
    mode_selector.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="w")
    if not SCAPY_AVAILABLE:
        mode_selector.configure(state="disabled")

    delay_label = ctk.CTkLabel(control, text="Delay between hosts (s)")
    delay_label.grid(row=2, column=2, padx=10, pady=5, sticky="w")
    delay_var = tk.DoubleVar(value=0.0)
    delay_entry = ctk.CTkEntry(control, width=80, textvariable=delay_var)
    delay_entry.grid(row=2, column=3, padx=10, pady=5, sticky="e")

    results_box = tk.Text(window, height=24, bg="black", fg="#00ff7f")
    results_box.pack(fill="both", expand=True, padx=30, pady=10)

    status_label = ctk.CTkLabel(window, text="Idle")
    status_label.pack(pady=(0, 10))

    scan_results: List[ScanResult] = []

    def append(message: str) -> None:
        results_box.insert(tk.END, message)
        results_box.see(tk.END)

    def scan_host(host: str, ports: List[int], mode: str) -> ScanResult:
        host = host.strip()
        open_ports: Dict[int, str] = {}
        if not host:
            return ScanResult(host, open_ports)
        if not host.startswith("http://") and not host.startswith("https://"):
            url = f"http://{host}"
        else:
            url = host
        if not is_url_in_scope(url):
            append(f"[!] {host} skipped (out of scope)\n")
            return ScanResult(host, open_ports)
        set_target(host)
        for port in ports:
            alive = False
            if mode == "syn" and SCAPY_AVAILABLE:
                alive = _syn_scan(host, port)
            else:
                alive = _connect_scan(host, port)
            if alive:
                open_ports[port] = "open"
                append(f"[+] {host}:{port} open\n")
        return ScanResult(host, open_ports)

    def run_scan() -> None:
        raw_hosts = [entry.strip() for entry in host_box.get("1.0", tk.END).splitlines() if entry.strip()]
        if not raw_hosts:
            messagebox.showerror("Hosts", "Provide at least one host or IP.")
            return
        ports = _parse_ports(ports_var.get())
        if not ports:
            messagebox.showerror("Ports", "No valid ports specified.")
            return
        mode = mode_var.get()
        max_threads = max(1, min(200, thread_var.get()))
        results_box.delete("1.0", tk.END)
        scan_results.clear()
        status_label.configure(text="Scanning...")

        def worker() -> None:
            from queue import Queue

            queue: "Queue[Tuple[str]]" = Queue()
            for host in raw_hosts:
                queue.put((host,))

            def consume() -> None:
                while not queue.empty():
                    host_tuple = queue.get()
                    host = host_tuple[0]
                    result = scan_host(host, ports, mode)
                    if result.open_ports:
                        scan_results.append(result)
                    queue.task_done()
                    time.sleep(max(delay_var.get(), 0))

            threads: List[threading.Thread] = []
            for _ in range(max_threads):
                t = threading.Thread(target=consume, daemon=True)
                threads.append(t)
                t.start()
            queue.join()
            status_label.configure(text=f"Completed ({len(scan_results)} host(s) with open ports)")

        threading.Thread(target=worker, daemon=True).start()

    run_button = ctk.CTkButton(window, text="Start Scan", command=run_scan)
    run_button.pack(pady=5)

    def export_results() -> None:
        if not scan_results:
            messagebox.showinfo("Export", "No findings to export yet.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not file_path:
            return
        with open(file_path, "w", encoding="utf-8") as handle:
            for result in scan_results:
                handle.write(f"Host: {result.host}\n")
                for port in sorted(result.open_ports):
                    handle.write(f"  - {port}/tcp open\n")
                handle.write("\n")
        messagebox.showinfo("Export", f"Saved to {file_path}")

    export_button = ctk.CTkButton(window, text="Export", command=export_results)
    export_button.pack(pady=(0, 10))

    close_button = ctk.CTkButton(window, text="Close", command=window.destroy)
    close_button.pack(pady=(0, 15))

    window.mainloop()
