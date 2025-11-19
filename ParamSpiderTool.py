from __future__ import annotations

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from tkinter import messagebox, filedialog
import tkinter as tk
from urllib.parse import parse_qsl, urlencode, urlsplit, quote

import customtkinter as ctk
import requests

from session_state import (
    get_target,
    set_target,
    is_url_in_scope,
    scope_error,
    describe_scope,
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

REQUEST_TIMEOUT = 5

DEFAULT_XSS_PAYLOADS = [
    "<script>alert(1337)</script>",
    '"/><svg onload=alert(1)>',
    "<img src=x onerror=alert(1)>",
]

DEFAULT_SQLI_PAYLOADS = [
    "' OR '1'='1",
    '" OR 1=1-- -',
    "admin')--",
]

SQL_ERROR_SIGNATURES = [
    'you have an error in your sql syntax',
    'warning: mysql',
    'unclosed quotation mark after the character string',
    'quoted string not properly terminated',
    'pg_query(): query failed',
    'sqlstate[',
]

USER_AGENTS = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
]


def param_spider_tool():
    window = create_tool_window("Parameter Spider", size=(1280, 860))
    header_text = (
        "Enumerate parameters with passive sources, mutate them with payloads, and tag "
        "probable XSS/SQLi/open redirect vectors in real time."
    )
    build_header(window, "Parameter Spider", header_text)
    content = build_content(window)
    content.grid_rowconfigure(0, weight=1)

    left_column = ctk.CTkFrame(content, fg_color="transparent")
    left_column.grid(row=0, column=0, sticky="nsew", padx=(0, 18))
    left_column.grid_rowconfigure(1, weight=1)

    controls_card = build_section_card(
        left_column,
        "Scan controls",
        "Define the base URL, concurrency, and pacing before fuzzing parameters.",
    )
    controls_card.pack(fill="x", pady=(0, 18))
    controls_card.grid_columnconfigure(1, weight=1)

    url_label = ctk.CTkLabel(controls_card, text="Target URL (https://example.com)")
    url_label.grid(row=0, column=0, padx=20, pady=(10, 4), sticky="w")
    url_entry = ctk.CTkEntry(controls_card)
    url_entry.grid(row=0, column=1, padx=20, pady=(10, 4), sticky="ew")
    if get_target():
        url_entry.insert(0, get_target())

    def load_global_target():
        target = get_target()
        if not target:
            messagebox.showinfo("Global Target", "No global target configured.")
            return
        url_entry.delete(0, tk.END)
        url_entry.insert(0, target)

    sync_button = ctk.CTkButton(controls_card, text="Use global target", command=load_global_target)
    sync_button.grid(row=0, column=2, padx=20, pady=(10, 4))

    thread_label = ctk.CTkLabel(controls_card, text="Threads (max 2000)")
    thread_label.grid(row=1, column=0, padx=20, pady=4, sticky="w")
    thread_entry = ctk.CTkEntry(controls_card)
    thread_entry.insert(0, "250")
    thread_entry.grid(row=1, column=1, padx=20, pady=4, sticky="ew")

    link_label = ctk.CTkLabel(controls_card, text="Max links to scan")
    link_label.grid(row=2, column=0, padx=20, pady=4, sticky="w")
    links_to_search_entry = ctk.CTkEntry(controls_card)
    links_to_search_entry.insert(0, "1000")
    links_to_search_entry.grid(row=2, column=1, padx=20, pady=4, sticky="ew")

    delay_label = ctk.CTkLabel(controls_card, text="Delay per request (ms)")
    delay_label.grid(row=3, column=0, padx=20, pady=(4, 16), sticky="w")
    delay_entry = ctk.CTkEntry(controls_card)
    delay_entry.insert(0, "0")
    delay_entry.grid(row=3, column=1, padx=20, pady=(4, 16), sticky="ew")

    controls_card.grid_columnconfigure(2, weight=0)

    payload_card = build_section_card(
        left_column,
        "Payload vault",
        "Paste custom payloads per vector. Defaults are provided when fields are left empty.",
    )
    payload_card.pack(fill="both", expand=True)
    payload_card.grid_columnconfigure((0, 1), weight=1)

    xss_label = ctk.CTkLabel(payload_card, text="XSS payloads")
    xss_label.grid(row=0, column=0, padx=20, pady=(6, 4), sticky="w")
    xss_payload_text = ctk.CTkTextbox(payload_card, height=150)
    xss_payload_text.grid(row=1, column=0, padx=20, pady=(0, 12), sticky="nsew")
    xss_payload_text.insert("1.0", "\n".join(DEFAULT_XSS_PAYLOADS))

    sqli_label = ctk.CTkLabel(payload_card, text="SQLi payloads")
    sqli_label.grid(row=0, column=1, padx=20, pady=(6, 4), sticky="w")
    sqli_payload_text = ctk.CTkTextbox(payload_card, height=150)
    sqli_payload_text.grid(row=1, column=1, padx=20, pady=(0, 12), sticky="nsew")
    sqli_payload_text.insert("1.0", "\n".join(DEFAULT_SQLI_PAYLOADS))

    right_column = ctk.CTkFrame(content, fg_color="transparent")
    right_column.grid(row=0, column=1, sticky="nsew")
    log_frame, results_text, append_log, clear_log = build_log_panel(right_column, "Live findings")
    log_frame.pack(fill="both", expand=True)

    status_var = tk.StringVar(value="Idle")
    scope_var = tk.StringVar(value=describe_scope())
    _status_bar, _scope_label = build_status_bar(window, status_var, scope_var)

    button_row = build_button_row(left_column)
    progress = ctk.CTkProgressBar(button_row, mode="indeterminate")
    progress.pack(fill="x", padx=20, pady=(0, 10))

    start_button: ctk.CTkButton

    def safe_log(message: str) -> None:
        results_text.after(0, lambda: (results_text.insert(tk.END, message + "\n"), results_text.see(tk.END)))

    def collect_payloads(widget: ctk.CTkTextbox, defaults: list[str]) -> list[str]:
        text = widget.get("1.0", tk.END)
        payloads = [line.strip() for line in text.splitlines() if line.strip()]
        return payloads or defaults

    def save_results() -> None:
        filename = filedialog.asksaveasfilename(defaultextension=".txt")
        if not filename:
            return
        with open(filename, "w", encoding="utf-8") as outfile:
            outfile.write(results_text.get("1.0", tk.END).strip())
        messagebox.showinfo("Saved", f"Log exported to {filename}")

    def finalize(status: str) -> None:
        status_var.set(status)
        progress.stop()
        if start_button:
            start_button.configure(state=tk.NORMAL)

    def run_scan() -> None:
        domain_input = url_entry.get().strip()
        if not domain_input:
            messagebox.showerror("Missing target", "Enter a domain or URL to scan.")
            finalize("Idle")
            return
        if not domain_input.startswith(("http://", "https://")):
            domain_input = f"https://{domain_input}"
            url_entry.delete(0, tk.END)
            url_entry.insert(0, domain_input)

        if not is_url_in_scope(domain_input):
            messagebox.showerror("Scope restriction", scope_error(domain_input))
            finalize("Idle")
            return

        set_target(domain_input)
        scope_var.set(describe_scope())

        try:
            max_thread_value = max(1, min(int(thread_entry.get() or 250), 2000))
        except ValueError:
            messagebox.showerror("Threads", "Thread count must be numeric.")
            finalize("Idle")
            return

        try:
            max_link_to_scan_value = max(1, int(links_to_search_entry.get() or 1000))
        except ValueError:
            messagebox.showerror("Link budget", "Link budget must be numeric.")
            finalize("Idle")
            return

        try:
            delay_ms = float(delay_entry.get() or 0)
        except ValueError:
            messagebox.showerror("Delay", "Request delay must be numeric (milliseconds).")
            finalize("Idle")
            return

        request_delay_seconds = max(0.0, delay_ms / 1000.0)
        xss_payloads = collect_payloads(xss_payload_text, DEFAULT_XSS_PAYLOADS)
        sqli_payloads = collect_payloads(sqli_payload_text, DEFAULT_SQLI_PAYLOADS)

        parsed_domain = urlsplit(domain_input)
        domain = parsed_domain.netloc or parsed_domain.path or domain_input

        safe_log(f"Collecting endpoints for {domain} ...")
        status_var.set("Gathering URLs")

        allurl = set()
        common_fetched_url = set()
        user_agent = random.choice(USER_AGENTS)

        def gather_from_alien_vault() -> None:
            try:
                response = requests.get(
                    f'https://otx.alienvault.com/api/v1/indicators/hostname/{quote(domain)}/url_list?limit=1000',
                    headers={'User-Agent': user_agent},
                    timeout=REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                response_json = response.json()
                for request_url in response_json.get('url_list', []):
                    url_value = request_url.get('url')
                    if not url_value or not is_url_in_scope(url_value):
                        continue
                    allurl.add(url_value)
                    if '?' in url_value and '=' in url_value:
                        common_fetched_url.add(url_value)
            except requests.RequestException as exc:
                safe_log(f"AlienVault lookup failed: {exc}")
            except ValueError:
                safe_log("AlienVault returned invalid JSON.")

        def gather_from_wayback() -> None:
            wayback_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            try:
                response = requests.get(wayback_url, headers={'User-Agent': user_agent}, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                load = response.json()
                for ur in load:
                    url_value = ur[0]
                    if not url_value or not is_url_in_scope(url_value):
                        continue
                    allurl.add(url_value)
                    if '?' in url_value and '=' in url_value:
                        common_fetched_url.add(url_value)
            except requests.RequestException as exc:
                safe_log(f"Wayback lookup failed: {exc}")
            except ValueError:
                safe_log("Wayback Machine returned invalid JSON.")

        gather_from_alien_vault()
        gather_from_wayback()

        safe_log(f"=>>> We found {len(allurl)} URLs from the passive sources")

        fetched_url = []
        link_count = 0
        for url_value in sorted(common_fetched_url):
            try:
                parsed = urlsplit(url_value)
            except ValueError:
                continue
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            if not query_pairs:
                continue
            mutated_query = urlencode([(key, 'FUZZ') for key, _ in query_pairs])
            mutated_url = parsed._replace(query=mutated_query).geturl()
            if mutated_url not in fetched_url:
                fetched_url.append(mutated_url)
                link_count += 1
            if link_count >= max_link_to_scan_value:
                break

        if not fetched_url:
            safe_log("No parameterized URLs were discovered. Try expanding the scope or adding sources.")
            finalize("Finished")
            return

        safe_log(f"==>>> We will be scanning {len(fetched_url)} links!")
        status_var.set("Fuzzing parameters")

        def request_with_delay(url):
            try:
                headers = {'User-Agent': user_agent}
                response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                return response, None
            except requests.RequestException as exc:
                return None, exc
            finally:
                if request_delay_seconds:
                    time.sleep(request_delay_seconds)

        def scan_template(url_template):
            findings = {'xss': [], 'sqli': [], 'open_redirect': [], 'errors': []}
            for payload in xss_payloads:
                mutated_url = url_template.replace('FUZZ', quote(payload, safe=''))
                response, error = request_with_delay(mutated_url)
                if response is None:
                    findings['errors'].append(f"Request failed for {mutated_url}: {error}")
                    continue
                content = response.text.lower()
                if payload.lower() in content:
                    findings['xss'].append((mutated_url, payload))
                if '=http' in mutated_url:
                    findings['open_redirect'].append(mutated_url)

            for payload in sqli_payloads:
                mutated_url = url_template.replace('FUZZ', quote(payload, safe=''))
                response, error = request_with_delay(mutated_url)
                if response is None:
                    findings['errors'].append(f"Request failed for {mutated_url}: {error}")
                    continue
                content = response.text.lower()
                if any(signature in content for signature in SQL_ERROR_SIGNATURES):
                    findings['sqli'].append((mutated_url, payload))

            return findings

        found_links = set()
        open_redirect = set()
        sqli_findings = set()
        errors = []

        try:
            with ThreadPoolExecutor(max_workers=max_thread_value) as pool:
                response_list = list(pool.map(scan_template, fetched_url))
            for result in response_list:
                found_links.update(result['xss'])
                open_redirect.update(result['open_redirect'])
                sqli_findings.update(result['sqli'])
                errors.extend(result['errors'])
        except Exception as exc:  # pragma: no cover - defensive
            safe_log(f"Validation failed: {exc}")

        if found_links:
            safe_log('\n#######################-  Possible XSS Vectors  -###########################')
            for url_value, payload in sorted(found_links):
                safe_log(f"Potential XSS vector: {url_value} | Payload: {payload}")
        if sqli_findings:
            safe_log('\n#######################-  Possible SQLi Vectors  -###########################')
            for url_value, payload in sorted(sqli_findings):
                safe_log(f"Potential SQLi vector: {url_value} | Payload: {payload}")
        if open_redirect:
            safe_log('\n#######################-  Possible Open Redirects  -###########################')
            for links in sorted(open_redirect):
                safe_log(links)
        if not (found_links or open_redirect or sqli_findings):
            safe_log('\n#######################-  Result   -###########################')
            safe_log('We could not find anything :(')

        if errors:
            safe_log('\nSome requests failed and were skipped:')
            for entry in errors[:20]:
                safe_log(entry)
            if len(errors) > 20:
                safe_log(f"...and {len(errors) - 20} more failures.")

        with open('url.txt', 'w', encoding='utf-16') as f:
            for urls in sorted(allurl):
                f.write(f"{urls}\n")
        safe_log("URLs are saved to url.txt")
        safe_log('\nLog findings exported via Save Log for payload evidence.')
        finalize("Finished")

    def start_scan():
        nonlocal start_button
        clear_log()
        status_var.set("Preparing scan...")
        progress.start()
        start_button.configure(state=tk.DISABLED)
        threading.Thread(target=run_scan, daemon=True).start()

    def clear_log_action():
        clear_log()
        safe_log("Log cleared.")

    start_button = ctk.CTkButton(button_row, text="Start program", command=start_scan)
    start_button.pack(side="left", padx=(20, 10), pady=(10, 6))
    save_button = ctk.CTkButton(button_row, text="Save log", command=save_results)
    save_button.pack(side="left", padx=10, pady=(10, 6))
    clear_button = ctk.CTkButton(button_row, text="Clear log", command=clear_log_action)
    clear_button.pack(side="left", padx=10, pady=(10, 6))
    close_button = ctk.CTkButton(button_row, text="Close", command=window.destroy)
    close_button.pack(side="right", padx=20, pady=(10, 6))

    attach_modal_behavior(window)
