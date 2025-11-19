import threading
from tkinter import *
import tkinter as tk
from tkinter import filedialog, messagebox
import json
from concurrent.futures import ThreadPoolExecutor
import random
import time
from PIL import ImageTk
import requests
from urllib.parse import urlsplit, parse_qsl, urlencode
from urllib.parse import quote
import customtkinter as ctk
from PIL import Image
from ui_utils import open_image
from session_state import (
    get_target,
    set_target,
    is_url_in_scope,
    scope_error,
    describe_scope,
)

REQUEST_TIMEOUT = 5

DEFAULT_XSS_PAYLOADS = [
    "<script>alert(1337)</script>",
    "\"/><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
]

DEFAULT_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR 1=1-- -",
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


def param_spider_tool():
    # set the appearance mode
    ctk.set_appearance_mode("dark")
    # set the default color theme
    ctk.set_default_color_theme("dark-blue")
    # create a window
    param_spider_window = ctk.CTkToplevel()
    # set the title of the window
    param_spider_window.geometry("1000x700")
    # set the title of the window
    param_spider_window.title("Parameter Spider Tool")
    # set the background color of the window
    param_spider_window.configure(bg="#1e88e5")
    # set the window to be resizable
    param_spider_window.resizable(True, True)

    # Open the image file
    img = open_image("dark.png")

    # Resize the image to fit the window size
    img = img.resize((param_spider_window.winfo_screenwidth(), param_spider_window.winfo_screenheight()), Image.BICUBIC)
    img = img.convert('RGB')
    # Create a PhotoImage object from the resized image
    bg_img = ImageTk.PhotoImage(img)

    # Create a Label widget with the image as background
    bg_label = ctk.CTkLabel(param_spider_window, image=bg_img)
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    results_frame = ctk.CTkFrame(param_spider_window)
    results_frame.place(relx=0.5, rely=0.55, relwidth=0.9, relheight=0.35, anchor=CENTER)
    results_text = tk.Text(results_frame, bg="black", fg="white", wrap=tk.WORD)
    results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    results_scroll = tk.Scrollbar(results_frame, command=results_text.yview)
    results_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    results_text.configure(yscrollcommand=results_scroll.set)

    def log_message(message: str):
        results_text.insert(tk.END, message + "\n")
        results_text.see(tk.END)

    def collect_payloads(widget: tk.Text, defaults):
        text = widget.get('1.0', tk.END)
        payloads = [line.strip() for line in text.splitlines() if line.strip()]
        return payloads or defaults

    def paramSpider():

        user_agent_list = [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        ]

        user_agent = random.choice(user_agent_list)

        fetched_url = []
        common_fetched_url = set()

        domain_input = url_entry.get().strip()
        if not domain_input:
            messagebox.showerror("Error", "Enter a domain to scan (example: example.com)")
            label.configure(text="Idle")
            start_program_button.configure(state=tk.NORMAL)
            return

        if not is_url_in_scope(domain_input):
            messagebox.showerror("Scope Restriction", scope_error(domain_input))
            label.configure(text="Idle")
            start_program_button.configure(state=tk.NORMAL)
            return

        set_target(domain_input)

        parsed_domain = urlsplit(domain_input)
        domain = parsed_domain.netloc or parsed_domain.path or domain_input

        try:
            max_thread_value = int(thread_entry.get() or 1000)
        except ValueError:
            messagebox.showerror("Error", "Thread count must be numeric.")
            label.configure(text="Idle")
            start_program_button.configure(state=tk.NORMAL)
            return

        try:
            max_link_to_scan_value = int(links_to_search_entry.get() or 1000)
        except ValueError:
            messagebox.showerror("Error", "Link limit must be numeric.")
            label.configure(text="Idle")
            start_program_button.configure(state=tk.NORMAL)
            return

        try:
            delay_ms = float(delay_entry.get() or 0)
        except ValueError:
            messagebox.showerror("Error", "Request delay must be numeric (milliseconds).")
            label.configure(text="Idle")
            start_program_button.configure(state=tk.NORMAL)
            return

        request_delay_seconds = max(0.0, delay_ms / 1000.0)
        xss_payloads = collect_payloads(xss_payload_text, DEFAULT_XSS_PAYLOADS)
        sqli_payloads = collect_payloads(sqli_payload_text, DEFAULT_SQLI_PAYLOADS)

        max_thread_value = max(1, min(max_thread_value, 2000))
        max_link_to_scan_value = max(1, max_link_to_scan_value)

        log_message(f"Collecting endpoints for {domain} ...")
        label.configure(text="Gathering URLs...", font=("Courier", 15))

        allurl = set()

        try:
            response = requests.get(
                'https://otx.alienvault.com/api/v1/indicators/hostname/' + quote(domain) + '/url_list?limit=1000',
                headers={'User-Agent': user_agent}, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            response_json = response.json()
            for request_url in response_json.get('url_list', []):
                url_value = request_url.get('url')
                if not url_value:
                    continue
                if not is_url_in_scope(url_value):
                    continue
                allurl.add(url_value)
                if '?' in url_value and '=' in url_value:
                    common_fetched_url.add(url_value)
        except requests.RequestException as exc:
            log_message(f"AlienVault lookup failed: {exc}")
        except ValueError:
            log_message("AlienVault returned invalid JSON.")

        waybackURL = "https://web.archive.org/cdx/search/cdx?url=*." + domain + "&output=json&fl=original&collapse=urlkey"

        try:
            response = requests.get(waybackURL, headers={'User-Agent': user_agent}, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            load = response.json()
            for ur in load:
                url_value = ur[0]
                if not is_url_in_scope(url_value):
                    continue
                allurl.add(url_value)
                if '?' in url_value and '=' in url_value:
                    common_fetched_url.add(url_value)
        except requests.RequestException as exc:
            log_message(f"Wayback Machine lookup failed: {exc}")
        except ValueError:
            log_message("Wayback Machine returned invalid JSON.")

        for i in sorted(allurl):
            if '?' in i:
                log_message(i)
        log_message(f"=>>> We found {len(allurl)} URLs from the API results")

        link_count = 0
        for url in common_fetched_url:
            try:
                parsed = urlsplit(url)
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

        log_message(f"==>>> We will be scanning {len(fetched_url)} links!")

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

        if not fetched_url:
            log_message("No parameterized URLs were discovered. Try a different domain or increase the source depth.")
            label.configure(text="Finished", font=("Courier", 15))
            start_program_button.configure(state=tk.NORMAL)
            return

        try:
            with ThreadPoolExecutor(max_workers=max_thread_value) as pool:
                response_list = list(pool.map(scan_template, fetched_url))
            for result in response_list:
                found_links.update(result['xss'])
                open_redirect.update(result['open_redirect'])
                sqli_findings.update(result['sqli'])
                errors.extend(result['errors'])
        except Exception as exc:
            log_message(f"Validation failed: {exc}")

        if found_links:
            log_message('\n#######################-  Possible XSS Vectors  -###########################')
            for url_value, payload in sorted(found_links):
                log_message(f"Potential XSS vector: {url_value} | Payload: {payload}")
        if sqli_findings:
            log_message('\n#######################-  Possible SQLi Vectors  -###########################')
            for url_value, payload in sorted(sqli_findings):
                log_message(f"Potential SQLi vector: {url_value} | Payload: {payload}")
        if open_redirect:
            log_message('\n#######################-  Possible Open Redirects  -###########################')
            for links in sorted(open_redirect):
                log_message(links)
        if not (found_links or open_redirect or sqli_findings):
            log_message('\n#######################-  Result   -###########################')
            log_message('We could not find anything :( ')

        if errors:
            log_message('\nSome requests failed and were skipped:')
            for entry in errors[:20]:
                log_message(entry)
            if len(errors) > 20:
                log_message(f"...and {len(errors) - 20} more failures.")

        with open('url.txt', 'w', encoding='utf-16') as f:
            for urls in allurl:
                f.write('%s\n' % urls)
        log_message("URLs are saved to url.txt")
        label2.configure(text='\n#######################-  the results has been saved to a file named "url.txt"!\nUse the log export button for payload findings.  -###########################')
        label.configure(text="Request completed!!", font=("Courier", 15))
        start_program_button.configure(state=tk.NORMAL)

    # Thread
    def thread():
        # Update the status label to indicate that the program is running
        label.configure(text='Processing.....', font=("Courier", 15))
        start_program_button.configure(state=tk.DISABLED)
        scope_label.configure(text=describe_scope())
        results_text.delete('1.0', tk.END)
        threading.Thread(target=paramSpider, daemon=True).start()

    def save_results():
        filename = filedialog.asksaveasfilename(defaultextension='.txt')
        if not filename:
            return
        with open(filename, 'w', encoding='utf-8') as outfile:
            outfile.write(results_text.get('1.0', tk.END).strip())
        messagebox.showinfo("Saved", f"Results exported to {filename}")

    def back():
        param_spider_window.destroy()

    # GUI
    url_label = ctk.CTkLabel(master=param_spider_window, text="Enter URL :")
    # pack the label
    url_label.pack(side="left", anchor=NW, expand=True)
    # palce the label
    url_label.place(relx=0.01, rely=0)
    # configure the label
    url_label.configure(font=("Courier", 12), fg_color="black")
    # create the Entry
    url_entry = ctk.CTkEntry(master=param_spider_window)
    # pack the entry
    url_entry.pack(side="left", anchor=NE, expand=True)
    # pack the entry
    url_entry.place(relx=0.12, rely=0)
    if get_target():
        url_entry.insert(0, get_target())

    def load_global_target():
        target = get_target()
        if not target:
            messagebox.showinfo("Global Target", "No global target configured.")
            return
        url_entry.delete(0, tk.END)
        url_entry.insert(0, target)

    sync_button = ctk.CTkButton(master=param_spider_window, text="Use Global Target", command=load_global_target)
    sync_button.place(relx=0.12, rely=0.05)
    # create the button
    thread_label = ctk.CTkLabel(master=param_spider_window, text="MAX Threads to use\nDefault(1000) :")
    # pack the label
    thread_label.pack(side="left", anchor=NW, expand=True)
    # configure the label
    thread_label.place(relx=0.3, rely=0)
    # configure the label
    thread_label.configure(font=("Courier", 12), fg_color="black")
    # create the button
    thread_entry = ctk.CTkEntry(master=param_spider_window)
    # pack the entry
    thread_entry.pack(side="left", anchor=NW, expand=True)
    # pack the entry
    thread_entry.place(relx=0.44, rely=0)
    # create the button
    lniks_to_search_label = ctk.CTkLabel(master=param_spider_window,
                                         text="how many links\nyou want to scan\n(default 1000) :")
    # pack the label
    lniks_to_search_label.pack(side="left", anchor=NW, expand=True)
    # configure the label
    lniks_to_search_label.configure(font=("Courier", 12), fg_color="black")
    # pack the label
    lniks_to_search_label.place(relx=0.61, rely=0)
    # create the button
    links_to_search_entry = ctk.CTkEntry(master=param_spider_window)
    # pack the entry
    links_to_search_entry.pack(side="left", anchor=NW, expand=True)
    # pack the entry
    links_to_search_entry.place(relx=0.75, rely=0)
    # create the button
    label = ctk.CTkLabel(master=param_spider_window, text="not Running")
    # configure the label
    label.configure(font=("Courier", 15), fg_color="black")
    # pack the label
    label.pack(side="left", anchor=NW, expand=True)
    # pack the label
    label.place(relx=0.46, rely=0.7)
    # create the button
    label2 = ctk.CTkLabel(master=param_spider_window)
    # configure the label
    label2.configure(font=("Courier", 12))
    # pack the label
    label2.place(relx=0.5, rely=0.1, anchor=CENTER)

    scope_label = ctk.CTkLabel(master=param_spider_window, text=describe_scope())
    scope_label.place(relx=0.8, rely=0.05)
    # create the button
    legal_warnning_label = ctk.CTkLabel(master=param_spider_window,
                                        text="Legal Warning:\nUsage of this tool for attacking targets without prior mutual consent is illegal.\nIt is the end user's responsibility to obey all applicable federal laws.\nDevelopers assume no liability\n and are not responsible for any misuse or damage caused by this program")
    # configure the label
    legal_warnning_label.configure(font=("Courier", 16))
    # pack the label
    legal_warnning_label.pack(fill='both', expand=True, side='bottom')
    # place the label
    legal_warnning_label.place(relx=0.5, rely=0.9, anchor=CENTER)
    # create the label
    how_to_use_label = ctk.CTkLabel(master=param_spider_window,
                                    text="How to use:\n1-Enter the URL you want to scan (ex: orange.com)\n2-Enter the number of threads you want to use(ex:100)\n3-Enter the number of links you want to scan(ex: 100)\n4-Click on start program")
    # configure the label
    how_to_use_label.configure(font=("Courier", 20))
    # place the label
    how_to_use_label.place(relx=0.5, rely=0.5, anchor=CENTER)
    # open the image
    image = open_image("owasp.jpg")
    # resize the image
    image = image.resize((15, 15), Image.ANTIALIAS)
    # convert image to tkinter readable image format
    photo = ImageTk.PhotoImage(image)
    # create the button
    start_program_button = ctk.CTkButton(master=param_spider_window, image=photo, text="Start Program", command=thread)
    # place the button
    start_program_button.place(relx=0.45, rely=0.85, anchor=CENTER)

    delay_label = ctk.CTkLabel(master=param_spider_window, text="Delay per request (ms):")
    delay_label.place(relx=0.12, rely=0.07)
    delay_label.configure(font=("Courier", 12), fg_color="black")

    delay_entry = ctk.CTkEntry(master=param_spider_window)
    delay_entry.place(relx=0.32, rely=0.07)

    payload_frame = ctk.CTkFrame(param_spider_window, fg_color="#0B1320")
    payload_frame.place(relx=0.5, rely=0.25, anchor=CENTER, relwidth=0.9, relheight=0.25)

    xss_label = ctk.CTkLabel(payload_frame, text="XSS payloads (one per line):")
    xss_label.grid(row=0, column=0, padx=10, pady=5, sticky='w')
    xss_payload_text = tk.Text(payload_frame, height=5, width=50)
    xss_payload_text.grid(row=1, column=0, padx=10, pady=5, sticky='nsew')
    xss_payload_text.insert(tk.END, '\n'.join(DEFAULT_XSS_PAYLOADS))

    sqli_label = ctk.CTkLabel(payload_frame, text="SQLi payloads (one per line):")
    sqli_label.grid(row=0, column=1, padx=10, pady=5, sticky='w')
    sqli_payload_text = tk.Text(payload_frame, height=5, width=50)
    sqli_payload_text.grid(row=1, column=1, padx=10, pady=5, sticky='nsew')
    sqli_payload_text.insert(tk.END, '\n'.join(DEFAULT_SQLI_PAYLOADS))

    payload_frame.grid_columnconfigure(0, weight=1)
    payload_frame.grid_columnconfigure(1, weight=1)
    payload_frame.grid_rowconfigure(1, weight=1)

    save_button = ctk.CTkButton(master=param_spider_window, text="Save Log", command=save_results)
    save_button.place(relx=0.65, rely=0.85, anchor=CENTER)
    # create the back button
    back_button = ctk.CTkButton(master=param_spider_window, text="Back", command=back)
    # place the button
    back_button.place(relx=0.35, rely=0.8, anchor=CENTER)
    # start the GUI
    param_spider_window.mainloop()
