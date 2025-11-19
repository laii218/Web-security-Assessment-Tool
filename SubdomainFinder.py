import threading
from tkinter import filedialog, messagebox
import tkinter as tk

import customtkinter as ctk
import requests
from PIL import Image, ImageTk

from ui_utils import open_image
from session_state import (
    get_target,
    set_target,
    is_url_in_scope,
    scope_error,
    describe_scope,
)

REQUEST_TIMEOUT = 10


def subdomain_finder():
    ctk.set_appearance_mode('dark')
    ctk.set_default_color_theme('dark-blue')

    window = ctk.CTkToplevel()
    window.title('Subdomain Finder')
    window.geometry('1100x750')

    bg = open_image('dark.png')
    bg = bg.resize((window.winfo_screenwidth(), window.winfo_screenheight()), Image.BICUBIC)
    bg_photo = ImageTk.PhotoImage(bg)
    bg_label = tk.Label(window, image=bg_photo)
    bg_label.image = bg_photo
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    results_frame = ctk.CTkFrame(window)
    results_frame.place(relx=0.5, rely=0.6, relwidth=0.9, relheight=0.55, anchor='center')
    results_text = tk.Text(results_frame, bg='black', fg='white', wrap=tk.WORD)
    results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    results_scroll = tk.Scrollbar(results_frame, command=results_text.yview)
    results_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    results_text.configure(yscrollcommand=results_scroll.set)

    status_label = ctk.CTkLabel(window, text='Idle')
    status_label.place(relx=0.5, rely=0.18, anchor='center')

    scope_label = ctk.CTkLabel(window, text=describe_scope())
    scope_label.place(relx=0.5, rely=0.22, anchor='center')

    domain_label = ctk.CTkLabel(window, text='Domain (example.com):')
    domain_label.place(relx=0.05, rely=0.05)
    domain_entry = ctk.CTkEntry(window, width=350)
    domain_entry.place(relx=0.32, rely=0.05)
    if get_target():
        domain_entry.insert(0, get_target())

    def load_global_target():
        target = get_target()
        if not target:
            messagebox.showinfo('Global Target', 'No global target configured.')
            return
        domain_entry.delete(0, tk.END)
        domain_entry.insert(0, target)

    sync_button = ctk.CTkButton(window, text='Use Global Target', command=load_global_target)
    sync_button.place(relx=0.7, rely=0.05)

    def append_result(message: str):
        def _append():
            results_text.insert(tk.END, message + '\n')
            results_text.see(tk.END)
        results_text.after(0, _append)

    def fetch_crtsh(domain: str):
        try:
            resp = requests.get(
                f'https://crt.sh/',
                params={'q': f'%.{domain}', 'output': 'json'},
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            results = set()
            for entry in data:
                names = entry.get('name_value', '')
                for name in names.split('\n'):
                    name = name.strip().lower()
                    if name:
                        results.add(name)
            return results
        except requests.RequestException as exc:
            append_result(f'crt.sh failed: {exc}')
        except ValueError:
            append_result('crt.sh returned invalid JSON')
        return set()

    def fetch_sonar(domain: str):
        try:
            resp = requests.get(f'https://sonar.omnisint.io/subdomains/{domain}', timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            return {item.strip().lower() for item in data if isinstance(item, str)}
        except requests.RequestException as exc:
            append_result(f'Sonar lookup failed: {exc}')
        except ValueError:
            append_result('Sonar returned invalid JSON data.')
        return set()

    def fetch_alienvault(domain: str):
        try:
            resp = requests.get(
                f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            results = set()
            for entry in data.get('passive_dns', []):
                host = entry.get('hostname')
                if host:
                    results.add(host.lower())
            return results
        except requests.RequestException as exc:
            append_result(f'AlienVault lookup failed: {exc}')
        except ValueError:
            append_result('AlienVault returned invalid JSON data.')
        return set()

    def run_lookup():
        domain = domain_entry.get().strip()
        if not domain:
            messagebox.showerror('Missing domain', 'Enter a domain to enumerate subdomains for.')
            return
        set_target(domain)
        if not is_url_in_scope(domain):
            messagebox.showerror('Scope Restriction', scope_error(domain))
            return

        results_text.delete('1.0', tk.END)
        status_label.configure(text='Running lookups...')
        scope_label.configure(text=describe_scope())

        def worker():
            discovered = set()
            for fetcher in (fetch_crtsh, fetch_sonar, fetch_alienvault):
                discovered.update(fetcher(domain))
            filtered = sorted(sub for sub in discovered if is_url_in_scope(f'https://{sub}'))
            if not filtered:
                append_result('No subdomains found inside the current scope.')
            else:
                append_result(f'Found {len(filtered)} in-scope subdomains:')
                for sub in filtered:
                    append_result(sub)
            status_label.after(0, lambda: status_label.configure(text='Finished'))

        threading.Thread(target=worker, daemon=True).start()

    def save_results():
        content = results_text.get('1.0', tk.END).strip()
        if not content:
            messagebox.showinfo('Save Results', 'No results to save.')
            return
        file_path = filedialog.asksaveasfilename(defaultextension='.txt')
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as outfile:
                outfile.write(content + '\n')
            messagebox.showinfo('Saved', f'Subdomains saved to {file_path}')

    run_button = ctk.CTkButton(window, text='Enumerate', command=run_lookup)
    run_button.place(relx=0.5, rely=0.1, anchor='center')

    save_button = ctk.CTkButton(window, text='Save Results', command=save_results)
    save_button.place(relx=0.65, rely=0.1, anchor='center')

    close_button = ctk.CTkButton(window, text='Close', command=window.destroy)
    close_button.place(relx=0.8, rely=0.1, anchor='center')

    legal = ctk.CTkLabel(window, text='Legal Warning: Use this tool responsibly and only against systems you are authorized to test.')
    legal.place(relx=0.5, rely=0.93, anchor='center')
