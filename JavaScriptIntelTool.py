import re
import threading
from dataclasses import dataclass, field
from typing import List, Tuple
from urllib.parse import urljoin, urlparse
import time

import customtkinter as ctk
import requests
import tkinter as tk
from PIL import ImageTk
from bs4 import BeautifulSoup
from tkinter import filedialog, messagebox

from session_state import (
    describe_scope,
    get_target,
    is_url_in_scope,
    scope_error,
    set_target,
)
from ui_utils import open_image

REQUEST_TIMEOUT = 10
URL_PATTERN = re.compile(r"https?://[\w\-./:?=&%#]+", re.IGNORECASE)
PATH_PATTERN = re.compile(r"(?:\.|/)[\w\-./]+", re.IGNORECASE)
SECRET_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})"), "Credential"),
    (re.compile(r"(?i)(aws|gcp|azure)[A-Za-z]+['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+]{16,})"), "Cloud Key"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.]+"), "Bearer Token"),
]


@dataclass
class ScriptFinding:
    source: str
    urls: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)

    def to_report(self) -> str:
        output = [f"Source: {self.source}"]
        if self.urls:
            output.append("  URLs:")
            output.extend(f"    - {url}" for url in sorted(set(self.urls)))
        if self.paths:
            output.append("  Paths:")
            output.extend(f"    - {path}" for path in sorted(set(self.paths)))
        if self.secrets:
            output.append("  Secrets / Tokens:")
            output.extend(f"    - {token}" for token in sorted(set(self.secrets)))
        return "\n".join(output) + "\n\n"


def javascript_intel_tool() -> None:
    window = ctk.CTkToplevel()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    window.geometry("1100x780")
    window.title("JavaScript Intel Extractor")

    background_image = open_image("dark.png")
    background_image = background_image.resize((window.winfo_screenwidth(), window.winfo_screenheight()))
    background_photo = ImageTk.PhotoImage(background_image)
    background_label = tk.Label(window, image=background_photo)
    background_label.image = background_photo
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    header = ctk.CTkLabel(window, text="Extract URLs, paths, secrets, and clues from JavaScript", font=("Segoe UI", 20, "bold"))
    header.pack(pady=12)

    scope_label = ctk.CTkLabel(window, text=describe_scope())
    scope_label.pack(pady=(0, 6))

    control_frame = ctk.CTkFrame(window)
    control_frame.pack(fill="x", padx=30, pady=10)

    url_label = ctk.CTkLabel(control_frame, text="Seed URL")
    url_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

    url_var = tk.StringVar(value=get_target())
    url_entry = ctk.CTkEntry(control_frame, width=420, textvariable=url_var)
    url_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

    def load_global_target() -> None:
        target = get_target()
        if not target:
            messagebox.showinfo("Global Target", "No target configured in the dashboard.")
            return
        url_var.set(target)

    load_button = ctk.CTkButton(control_frame, text="Use Global Target", command=load_global_target)
    load_button.grid(row=0, column=2, padx=10, pady=10)

    follow_external_var = tk.IntVar(value=0)
    inline_var = tk.IntVar(value=1)

    follow_external = ctk.CTkCheckBox(
        control_frame, text="Follow third-party script URLs", variable=follow_external_var, onvalue=1, offvalue=0
    )
    follow_external.grid(row=1, column=0, padx=10, pady=5, sticky="w")

    inline_only = ctk.CTkCheckBox(
        control_frame, text="Capture inline <script> blocks", variable=inline_var, onvalue=1, offvalue=0
    )
    inline_only.grid(row=1, column=1, padx=10, pady=5, sticky="w")

    rate_label = ctk.CTkLabel(control_frame, text="Request delay (seconds)")
    rate_label.grid(row=1, column=2, padx=10, pady=5, sticky="e")
    delay_var = tk.DoubleVar(value=0.2)
    rate_entry = ctk.CTkEntry(control_frame, width=80, textvariable=delay_var)
    rate_entry.grid(row=1, column=3, padx=10, pady=5)

    results_box = tk.Text(window, height=24, width=140, bg="black", fg="lime", insertbackground="white")
    results_box.pack(fill="both", expand=True, padx=30, pady=10)

    status_label = ctk.CTkLabel(window, text="Idle")
    status_label.pack(pady=(0, 10))

    findings: List[ScriptFinding] = []

    def append(message: str) -> None:
        results_box.insert(tk.END, message)
        results_box.see(tk.END)

    def fetch_scripts(seed_url: str) -> List[Tuple[str, str]]:
        scripts: List[Tuple[str, str]] = []
        parsed_seed = urlparse(seed_url)
        try:
            response = requests.get(seed_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
        except requests.RequestException as exc:
            append(f"Failed to fetch {seed_url}: {exc}\n")
            return scripts
        time.sleep(max(delay_var.get(), 0))
        soup = BeautifulSoup(response.text, "html.parser")
        for idx, tag in enumerate(soup.find_all("script")):
            src = tag.get("src")
            if src:
                script_url = urljoin(seed_url, src)
                if not follow_external_var.get():
                    if urlparse(script_url).netloc != parsed_seed.netloc:
                        append(f"Skipping third-party script: {script_url}\n")
                        continue
                if not is_url_in_scope(script_url):
                    append(f"Skipping out-of-scope script: {script_url}\n")
                    continue
                try:
                    js_response = requests.get(script_url, timeout=REQUEST_TIMEOUT)
                    js_response.raise_for_status()
                    scripts.append((script_url, js_response.text))
                    time.sleep(max(delay_var.get(), 0))
                except requests.RequestException as exc:
                    append(f"Failed to fetch {script_url}: {exc}\n")
            else:
                if inline_var.get():
                    body = tag.string or tag.text or ""
                    scripts.append((f"{seed_url}#inline-{idx+1}", body))
        return scripts

    def analyze_content(source: str, content: str) -> ScriptFinding:
        finding = ScriptFinding(source=source)
        finding.urls = URL_PATTERN.findall(content)
        finding.paths = [path for path in PATH_PATTERN.findall(content) if len(path) > 4 and "." in path]
        for pattern, label in SECRET_PATTERNS:
            for match in pattern.findall(content):
                token = match[1] if isinstance(match, tuple) else match
                finding.secrets.append(f"{label}: {token}")
        return finding

    def run_analysis() -> None:
        seed = url_var.get().strip()
        if not seed:
            messagebox.showerror("Missing URL", "Provide a starting URL to analyze.")
            return
        if not is_url_in_scope(seed):
            messagebox.showerror("Scope", scope_error(seed))
            return
        set_target(seed)
        scope_label.configure(text=describe_scope())
        results_box.delete("1.0", tk.END)
        status_label.configure(text="Collecting scripts...")
        findings.clear()

        def worker() -> None:
            scripts = fetch_scripts(seed)
            if not scripts:
                status_label.configure(text="No scripts discovered.")
                return
            append(f"Discovered {len(scripts)} scripts.\n")
            for source, body in scripts:
                finding = analyze_content(source, body)
                findings.append(finding)
                append(finding.to_report())
            status_label.configure(text=f"Completed ({len(findings)} scripts analyzed)")

        threading.Thread(target=worker, daemon=True).start()

    analyze_button = ctk.CTkButton(window, text="Analyze JavaScript", command=run_analysis)
    analyze_button.pack(pady=10)

    def export_results() -> None:
        if not findings:
            messagebox.showinfo("Export", "No findings to export yet.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not file_path:
            return
        with open(file_path, "w", encoding="utf-8") as handle:
            for finding in findings:
                handle.write(finding.to_report())
        messagebox.showinfo("Export", f"Findings saved to {file_path}")

    export_button = ctk.CTkButton(window, text="Export Findings", command=export_results)
    export_button.pack(pady=(0, 15))

    back_button = ctk.CTkButton(window, text="Close", command=window.destroy)
    back_button.pack(pady=(0, 20))

    window.mainloop()
