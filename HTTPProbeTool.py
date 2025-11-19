import threading
import time
from typing import List

import customtkinter as ctk
import requests
import tkinter as tk
from PIL import ImageTk
from tkinter import filedialog, messagebox

from session_state import (
    describe_scope,
    get_target,
    is_url_in_scope,
)
from ui_utils import open_image

REQUEST_TIMEOUT = 6


def http_probe_tool() -> None:
    window = ctk.CTkToplevel()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    window.geometry("1100x760")
    window.title("HTTP/S Service Prober")

    background_image = open_image("dark.png")
    background_image = background_image.resize((window.winfo_screenwidth(), window.winfo_screenheight()))
    background_photo = ImageTk.PhotoImage(background_image)
    bg_label = tk.Label(window, image=background_photo)
    bg_label.image = background_photo
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    header = ctk.CTkLabel(window, text="Probe domains for responsive HTTP and HTTPS services", font=("Segoe UI", 22, "bold"))
    header.pack(pady=12)

    scope_label = ctk.CTkLabel(window, text=describe_scope())
    scope_label.pack(pady=(0, 10))

    control_frame = ctk.CTkFrame(window)
    control_frame.pack(fill="x", padx=30, pady=10)

    domains_box = ctk.CTkTextbox(control_frame, width=500, height=160)
    domains_box.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

    if get_target():
        domains_box.insert("1.0", get_target())

    control_frame.grid_columnconfigure(0, weight=1)

    def load_list() -> None:
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt")])
        if not path:
            return
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            domains = [line.strip() for line in handle if line.strip()]
        domains_box.delete("1.0", tk.END)
        domains_box.insert("1.0", "\n".join(domains))

    load_button = ctk.CTkButton(control_frame, text="Load Domains", command=load_list)
    load_button.grid(row=0, column=3, padx=10, pady=10)

    delay_label = ctk.CTkLabel(control_frame, text="Delay between probes (s)")
    delay_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
    delay_var = tk.DoubleVar(value=0.15)
    delay_entry = ctk.CTkEntry(control_frame, width=80, textvariable=delay_var)
    delay_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

    threads_label = ctk.CTkLabel(control_frame, text="Concurrent threads")
    threads_label.grid(row=1, column=2, padx=10, pady=5, sticky="e")
    thread_var = tk.IntVar(value=10)
    thread_entry = ctk.CTkEntry(control_frame, width=80, textvariable=thread_var)
    thread_entry.grid(row=1, column=3, padx=10, pady=5)

    results_box = tk.Text(window, bg="black", fg="white", height=24)
    results_box.pack(fill="both", expand=True, padx=30, pady=10)

    status_label = ctk.CTkLabel(window, text="Idle")
    status_label.pack(pady=(0, 10))

    findings: List[str] = []

    def append(message: str) -> None:
        results_box.insert(tk.END, message)
        results_box.see(tk.END)

    def probe_domain(domain: str) -> None:
        domain = domain.strip().lower()
        if not domain:
            return
        for scheme in ("http", "https"):
            url = f"{scheme}://{domain}"
            if not is_url_in_scope(url):
                append(f"[!] Skipping out-of-scope host: {url}\n")
                continue
            try:
                response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                findings.append(f"{url} -> {response.status_code}")
                append(f"[+] {url} is up ({response.status_code})\n")
            except requests.RequestException as exc:
                append(f"[-] {url} failed: {exc}\n")
            time.sleep(max(delay_var.get(), 0))

    def run_probe() -> None:
        raw = domains_box.get("1.0", tk.END)
        domains = sorted({entry.strip() for entry in raw.splitlines() if entry.strip()})
        if not domains:
            messagebox.showerror("Domains", "Provide at least one domain to probe.")
            return
        threads = max(1, min(50, thread_var.get()))
        results_box.delete("1.0", tk.END)
        status_label.configure(text=f"Probing {len(domains)} domain(s)...")

        def worker() -> None:
            from queue import Queue

            queue: "Queue[str]" = Queue()
            for domain in domains:
                queue.put(domain)

            def consume() -> None:
                while not queue.empty():
                    entry = queue.get()
                    probe_domain(entry)
                    queue.task_done()

            workers = []
            for _ in range(threads):
                t = threading.Thread(target=consume, daemon=True)
                workers.append(t)
                t.start()
            queue.join()
            status_label.configure(text=f"Completed ({len(findings)} responsive hosts)")

        threading.Thread(target=worker, daemon=True).start()

    run_button = ctk.CTkButton(window, text="Start Probe", command=run_probe)
    run_button.pack(pady=5)

    def export_results() -> None:
        if not findings:
            messagebox.showinfo("Export", "No successful probes recorded yet.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not file_path:
            return
        with open(file_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(findings))
        messagebox.showinfo("Export", f"Saved to {file_path}")

    export_button = ctk.CTkButton(window, text="Export", command=export_results)
    export_button.pack(pady=(0, 10))

    close_button = ctk.CTkButton(window, text="Close", command=window.destroy)
    close_button.pack(pady=(0, 15))

    window.mainloop()
