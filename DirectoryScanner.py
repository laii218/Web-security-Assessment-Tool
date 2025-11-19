from __future__ import annotations

import queue
import threading
import time
from urllib.parse import urljoin

import customtkinter as ctk
import requests
import tkinter as tk
from tkinter import filedialog, messagebox

from session_state import (
    describe_scope,
    get_target,
    is_url_in_scope,
    scope_error,
    set_target,
)
from ui_layouts import (
    attach_modal_behavior,
    build_button_row,
    build_content,
    build_header,
    build_log_panel,
    build_section_card,
    build_status_bar,
    create_tool_window,
)

REQUEST_TIMEOUT = 8
DEFAULT_WORDS = [
    'admin', 'login', 'dashboard', 'uploads', 'backup', 'config', 'server-status',
    'phpinfo.php', 'test', 'staging', 'old', 'private', 'api', 'includes', 'assets'
]


def directory_scanner():
    window = create_tool_window("Directory Scanner", size=(1250, 820))
    build_header(
        window,
        "Directory Scanner",
        "Queue up wordlists, respect scope boundaries, and pace threads to uncover hidden panels and APIs.",
    )
    content = build_content(window)
    content.grid_rowconfigure(0, weight=1)

    left_column = ctk.CTkFrame(content, fg_color="transparent")
    left_column.grid(row=0, column=0, sticky="nsew", padx=(0, 18))

    controls_card = build_section_card(
        left_column,
        "Scan controls",
        "Set the target URL, optional custom wordlist, concurrency, and delay.",
    )
    controls_card.pack(fill="x", pady=(0, 18))
    controls_card.grid_columnconfigure(1, weight=1)

    url_label = ctk.CTkLabel(controls_card, text="Target URL (https://example.com)")
    url_label.grid(row=0, column=0, padx=20, pady=(12, 4), sticky="w")
    url_entry = ctk.CTkEntry(controls_card)
    url_entry.grid(row=0, column=1, padx=20, pady=(12, 4), sticky="ew")
    if get_target():
        url_entry.insert(0, get_target())

    def load_global_target():
        target = get_target()
        if not target:
            messagebox.showinfo('Global Target', 'No global target configured.')
            return
        url_entry.delete(0, tk.END)
        url_entry.insert(0, target)

    sync_button = ctk.CTkButton(controls_card, text='Use global target', command=load_global_target)
    sync_button.grid(row=0, column=2, padx=20, pady=(12, 4))

    wordlist_label = ctk.CTkLabel(controls_card, text='Wordlist file (optional)')
    wordlist_label.grid(row=1, column=0, padx=20, pady=4, sticky='w')
    wordlist_entry = ctk.CTkEntry(controls_card)
    wordlist_entry.grid(row=1, column=1, padx=20, pady=4, sticky='ew')

    def browse_wordlist():
        path = filedialog.askopenfilename()
        if path:
            wordlist_entry.delete(0, tk.END)
            wordlist_entry.insert(0, path)

    browse_button = ctk.CTkButton(controls_card, text='Browse', command=browse_wordlist)
    browse_button.grid(row=1, column=2, padx=20, pady=4)

    threads_label = ctk.CTkLabel(controls_card, text='Threads (max 100)')
    threads_label.grid(row=2, column=0, padx=20, pady=4, sticky='w')
    threads_entry = ctk.CTkEntry(controls_card)
    threads_entry.insert(0, '10')
    threads_entry.grid(row=2, column=1, padx=20, pady=4, sticky='ew')

    delay_label = ctk.CTkLabel(controls_card, text='Delay between requests (ms)')
    delay_label.grid(row=3, column=0, padx=20, pady=(4, 16), sticky='w')
    delay_entry = ctk.CTkEntry(controls_card)
    delay_entry.insert(0, '0')
    delay_entry.grid(row=3, column=1, padx=20, pady=(4, 16), sticky='ew')

    right_column = ctk.CTkFrame(content, fg_color="transparent")
    right_column.grid(row=0, column=1, sticky="nsew")
    log_frame, results_text, _, clear_log = build_log_panel(right_column, "Discovered paths")
    log_frame.pack(fill="both", expand=True)

    status_var = tk.StringVar(value='Idle')
    scope_var = tk.StringVar(value=describe_scope())
    build_status_bar(window, status_var, scope_var)

    button_row = build_button_row(left_column)

    stop_event = threading.Event()
    worker_threads: list[threading.Thread] = []

    def log(message: str) -> None:
        results_text.after(0, lambda: (results_text.insert(tk.END, message + '\n'), results_text.see(tk.END)))

    def load_wordlist():
        path = wordlist_entry.get().strip()
        if not path:
            return list(DEFAULT_WORDS)
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as infile:
                return [line.strip() for line in infile if line.strip()]
        except OSError as exc:
            messagebox.showerror('Wordlist Error', f'Failed to read wordlist: {exc}')
            return None

    def scan_worker(base_url: str, task_queue: queue.Queue, delay_seconds: float):
        while not stop_event.is_set():
            try:
                path = task_queue.get_nowait()
            except queue.Empty:
                return
            target = urljoin(base_url, path if path.startswith('/') else f'/{path}')
            if not is_url_in_scope(target):
                task_queue.task_done()
                continue
            try:
                response = requests.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                status = response.status_code
                if status in {200, 204, 301, 302, 307, 401, 403}:
                    log(f'[{status}] {target}')
            except requests.RequestException as exc:
                log(f'Error fetching {target}: {exc}')
            finally:
                task_queue.task_done()
                if delay_seconds:
                    time.sleep(delay_seconds)

    start_button: ctk.CTkButton
    stop_button: ctk.CTkButton

    def start_scan():
        nonlocal start_button, stop_button
        base_url = url_entry.get().strip()
        if not base_url:
            messagebox.showerror('Missing URL', 'Enter a target URL to scan.')
            return
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'http://' + base_url
            url_entry.delete(0, tk.END)
            url_entry.insert(0, base_url)
        if not is_url_in_scope(base_url):
            messagebox.showerror('Scope Restriction', scope_error(base_url))
            return
        set_target(base_url)
        scope_var.set(describe_scope())
        try:
            thread_count = max(1, min(100, int(threads_entry.get() or 10)))
        except ValueError:
            messagebox.showerror('Invalid threads', 'Threads must be numeric.')
            return
        try:
            delay_ms = float(delay_entry.get() or 0)
        except ValueError:
            messagebox.showerror('Invalid delay', 'Delay must be numeric (ms).')
            return
        delay_seconds = max(0.0, delay_ms / 1000.0)

        words = load_wordlist()
        if words is None:
            return
        if not words:
            messagebox.showerror('Wordlist Empty', 'No paths provided to scan.')
            return

        stop_event.clear()
        clear_log()
        status_var.set('Running...')
        start_button.configure(state=tk.DISABLED)
        stop_button.configure(state=tk.NORMAL)

        task_queue = queue.Queue()
        for entry in words:
            task_queue.put(entry)

        def monitor_queue():
            if task_queue.unfinished_tasks == 0 and not any(t.is_alive() for t in worker_threads):
                status_var.set('Finished')
                start_button.configure(state=tk.NORMAL)
                stop_button.configure(state=tk.DISABLED)
            else:
                window.after(250, monitor_queue)

        worker_threads.clear()
        for _ in range(thread_count):
            worker = threading.Thread(target=scan_worker, args=(base_url, task_queue, delay_seconds), daemon=True)
            worker_threads.append(worker)
            worker.start()

        monitor_queue()

    def stop_scan():
        nonlocal start_button, stop_button
        stop_event.set()
        status_var.set('Stopping...')
        start_button.configure(state=tk.NORMAL)
        stop_button.configure(state=tk.DISABLED)

    def save_results():
        filename = filedialog.asksaveasfilename(defaultextension='.txt')
        if filename:
            with open(filename, 'w', encoding='utf-8') as outfile:
                outfile.write(results_text.get('1.0', tk.END))
            messagebox.showinfo('Saved', f'Results saved to {filename}')

    start_button = ctk.CTkButton(button_row, text='Start scan', command=start_scan)
    start_button.pack(side='left', padx=(20, 10), pady=10)
    stop_button = ctk.CTkButton(button_row, text='Stop', command=stop_scan, state=tk.DISABLED)
    stop_button.pack(side='left', padx=10, pady=10)
    save_button = ctk.CTkButton(button_row, text='Save results', command=save_results)
    save_button.pack(side='left', padx=10, pady=10)
    close_button = ctk.CTkButton(button_row, text='Close', command=window.destroy)
    close_button.pack(side='right', padx=20, pady=10)

    attach_modal_behavior(window)
