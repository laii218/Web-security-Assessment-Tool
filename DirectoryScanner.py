import threading
import queue
import time
from urllib.parse import urljoin

import customtkinter as ctk
import requests
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

from ui_utils import open_image
from session_state import (
    get_target,
    set_target,
    is_url_in_scope,
    scope_error,
    describe_scope,
)

REQUEST_TIMEOUT = 8
DEFAULT_WORDS = [
    'admin', 'login', 'dashboard', 'uploads', 'backup', 'config', 'server-status',
    'phpinfo.php', 'test', 'staging', 'old', 'private', 'api', 'includes', 'assets'
]


def directory_scanner():
    ctk.set_appearance_mode('dark')
    ctk.set_default_color_theme('dark-blue')

    window = ctk.CTkToplevel()
    window.title('Directory Scanner')
    window.geometry('1200x800')
    window.configure(bg='#0B1320')

    bg_img = open_image('dark.png')
    bg_img = bg_img.resize((window.winfo_screenwidth(), window.winfo_screenheight()), Image.BICUBIC)
    bg_photo = ImageTk.PhotoImage(bg_img)
    bg_label = tk.Label(window, image=bg_photo)
    bg_label.image = bg_photo
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    results_frame = ctk.CTkFrame(window)
    results_frame.place(relx=0.5, rely=0.6, relwidth=0.9, relheight=0.5, anchor='center')
    results_text = tk.Text(results_frame, bg='black', fg='white', wrap=tk.WORD)
    results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    results_scroll = tk.Scrollbar(results_frame, command=results_text.yview)
    results_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    results_text.configure(yscrollcommand=results_scroll.set)

    def log(message: str):
        def append():
            results_text.insert(tk.END, message + '\n')
            results_text.see(tk.END)

        results_text.after(0, append)

    url_label = ctk.CTkLabel(window, text='Target URL (https://example.com):')
    url_label.place(relx=0.05, rely=0.05)
    url_entry = ctk.CTkEntry(window, width=400)
    url_entry.place(relx=0.32, rely=0.05)
    if get_target():
        url_entry.insert(0, get_target())

    def load_global_target():
        target = get_target()
        if not target:
            messagebox.showinfo('Global Target', 'No global target configured.')
            return
        url_entry.delete(0, tk.END)
        url_entry.insert(0, target)

    sync_button = ctk.CTkButton(window, text='Use Global Target', command=load_global_target)
    sync_button.place(relx=0.75, rely=0.05)

    wordlist_label = ctk.CTkLabel(window, text='Wordlist file (optional):')
    wordlist_label.place(relx=0.05, rely=0.1)
    wordlist_entry = ctk.CTkEntry(window, width=300)
    wordlist_entry.place(relx=0.32, rely=0.1)

    def browse_wordlist():
        path = filedialog.askopenfilename()
        if path:
            wordlist_entry.delete(0, tk.END)
            wordlist_entry.insert(0, path)

    browse_button = ctk.CTkButton(window, text='Browse', command=browse_wordlist)
    browse_button.place(relx=0.58, rely=0.1)

    threads_label = ctk.CTkLabel(window, text='Threads:')
    threads_label.place(relx=0.05, rely=0.15)
    threads_entry = ctk.CTkEntry(window, width=80)
    threads_entry.insert(0, '10')
    threads_entry.place(relx=0.15, rely=0.15)

    delay_label = ctk.CTkLabel(window, text='Delay between requests (ms):')
    delay_label.place(relx=0.25, rely=0.15)
    delay_entry = ctk.CTkEntry(window, width=120)
    delay_entry.insert(0, '0')
    delay_entry.place(relx=0.45, rely=0.15)

    status_label = ctk.CTkLabel(window, text='Idle')
    status_label.place(relx=0.05, rely=0.2)
    scope_label = ctk.CTkLabel(window, text=describe_scope())
    scope_label.place(relx=0.3, rely=0.2)

    stop_event = threading.Event()
    worker_threads = []

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

    def start_scan():
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
        scope_label.configure(text=describe_scope())
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
        results_text.delete('1.0', tk.END)
        status_label.configure(text='Running...')
        start_button.configure(state=tk.DISABLED)
        stop_button.configure(state=tk.NORMAL)

        task_queue = queue.Queue()
        for entry in words:
            task_queue.put(entry)

        def monitor_queue():
            if task_queue.unfinished_tasks == 0 and not any(t.is_alive() for t in worker_threads):
                status_label.configure(text='Finished')
                start_button.configure(state=tk.NORMAL)
                stop_button.configure(state=tk.DISABLED)
            else:
                window.after(200, monitor_queue)

        worker_threads.clear()
        for _ in range(thread_count):
            worker = threading.Thread(target=scan_worker, args=(base_url, task_queue, delay_seconds), daemon=True)
            worker_threads.append(worker)
            worker.start()

        monitor_queue()

    def stop_scan():
        stop_event.set()
        status_label.configure(text='Stopping...')
        start_button.configure(state=tk.NORMAL)
        stop_button.configure(state=tk.DISABLED)

    def save_results():
        filename = filedialog.asksaveasfilename(defaultextension='.txt')
        if filename:
            with open(filename, 'w', encoding='utf-8') as outfile:
                outfile.write(results_text.get('1.0', tk.END))
            messagebox.showinfo('Saved', f'Results saved to {filename}')

    start_button = ctk.CTkButton(window, text='Start Scan', command=start_scan)
    start_button.place(relx=0.7, rely=0.15)
    stop_button = ctk.CTkButton(window, text='Stop', command=stop_scan, state=tk.DISABLED)
    stop_button.place(relx=0.82, rely=0.15)
    save_button = ctk.CTkButton(window, text='Save Results', command=save_results)
    save_button.place(relx=0.7, rely=0.22)
    close_button = ctk.CTkButton(window, text='Close', command=window.destroy)
    close_button.place(relx=0.82, rely=0.22)

    instructions = ctk.CTkLabel(window, text='Provide a base URL and optionally a custom wordlist to brute force directories.\n'
                                               'Adjust thread count and delay to tune request rate.')
    instructions.place(relx=0.5, rely=0.35, anchor='center')

    legal = ctk.CTkLabel(window, text='Legal Warning: Use this tool responsibly and only against systems you are authorized to test.')
    legal.place(relx=0.5, rely=0.9, anchor='center')

    window.mainloop()
