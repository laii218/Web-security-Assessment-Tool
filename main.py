from tkinter import *
from PIL import ImageTk, Image
from ScrapingTool import scraping
from vulnerability_scanner import vulnerability_scanner
from ParamSpiderTool import param_spider_tool
from Password_Operations import password_operations
from DirectoryScanner import directory_scanner
from SubdomainFinder import subdomain_finder
from adminpagesFinder import adminpagesFinder
from TechnologyProfiler import technology_profiler
from ScrapingWebsites import scraping_websites
from JavaScriptIntelTool import javascript_intel_tool
from HTTPProbeTool import http_probe_tool
from PortScannerTool import port_scanner_tool
import customtkinter
from ui_utils import open_image
from session_state import (
    get_target,
    set_target,
    set_scope_from_text,
    get_scope_text,
    describe_scope,
)


root = customtkinter.CTk()
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")
root.title("Web Security Assessment Tool")
root.geometry("1400x900")
root.configure(fg_color="#050c18")
root.resizable(True, True)


def build_banner():
    banner = customtkinter.CTkFrame(root, fg_color="#081224", corner_radius=0)
    banner.pack(fill="x")
    title = customtkinter.CTkLabel(
        banner, text="Web Security Assessment HQ", font=("Segoe UI", 32, "bold")
    )
    title.pack(anchor="w", padx=35, pady=(30, 6))
    subtitle = customtkinter.CTkLabel(
        banner,
        text=(
            "Coordinate recon, scanning, exploitation triage, and hygiene checks from a single hub.\n"
            "Define the scope once, then launch tuned tooling with consistent reporting and exports."
        ),
        font=("Segoe UI", 17),
        justify="left",
    )
    subtitle.pack(anchor="w", padx=35, pady=(0, 25))


build_banner()


# Global target and scope controls
target_scope_frame = customtkinter.CTkFrame(root, fg_color="#0f1c2e", corner_radius=18)
target_scope_frame.pack(fill="x", padx=30, pady=(20, 10))

global_target_var = StringVar(value=get_target())


def apply_global_target():
    set_target(global_target_var.get())
    target_status.configure(text=f"Target applied: {global_target_var.get() or 'None'}")


target_label = customtkinter.CTkLabel(
    target_scope_frame,
    text="Global Target (https://example.com):",
    font=("Segoe UI", 14, "bold"),
)
target_label.grid(row=0, column=0, padx=15, pady=(15, 5), sticky="w")
target_entry = customtkinter.CTkEntry(target_scope_frame, width=420, textvariable=global_target_var)
target_entry.grid(row=0, column=1, padx=10, pady=(15, 5), sticky="w")
target_button = customtkinter.CTkButton(target_scope_frame, text="Apply Target", command=apply_global_target)
target_button.grid(row=0, column=2, padx=10, pady=(15, 5))
target_status = customtkinter.CTkLabel(target_scope_frame, text=f"Current: {get_target() or 'None'}")
target_status.grid(row=0, column=3, padx=15, pady=(15, 5), sticky="e")

scope_label = customtkinter.CTkLabel(
    target_scope_frame,
    text="Scope (one host/path per line, supports *.example.com):",
    font=("Segoe UI", 14, "bold"),
)
scope_label.grid(row=1, column=0, padx=15, pady=(10, 5), sticky="nw")
scope_box = customtkinter.CTkTextbox(target_scope_frame, width=420, height=110)
scope_box.grid(row=1, column=1, padx=10, pady=(10, 15), sticky="w")
scope_box.insert("1.0", get_scope_text())


def apply_scope():
    set_scope_from_text(scope_box.get("1.0", END))
    scope_status.configure(text=describe_scope())


scope_button = customtkinter.CTkButton(target_scope_frame, text="Save Scope", command=apply_scope)
scope_button.grid(row=1, column=2, padx=10, pady=(10, 15))
scope_status = customtkinter.CTkLabel(target_scope_frame, text=describe_scope())
scope_status.grid(row=1, column=3, padx=15, pady=(10, 15), sticky="e")
target_scope_frame.grid_columnconfigure(1, weight=1)


# Operational guidance
insights_frame = customtkinter.CTkFrame(root, fg_color="#0b1728", corner_radius=18)
insights_frame.pack(fill="x", padx=30, pady=(0, 15))
insights_label = customtkinter.CTkLabel(
    insights_frame,
    text=(
        "Operational playbook:\n"
        "• Capture a fingerprint per host before fuzzing with ParamSpider or the vuln scanner.\n"
        "• Use rate controls generously to avoid bans on production targets.\n"
        "• Export results frequently so scope evidence, timelines, and audit trails stay aligned."
    ),
    font=("Segoe UI", 14),
    justify="left",
)
insights_label.pack(anchor="w", padx=25, pady=18)


# Tool grid
tools_frame = customtkinter.CTkScrollableFrame(root, fg_color="#050c18")
tools_frame.pack(fill="both", expand=True, padx=30, pady=(0, 20))
tools_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="tools")


def build_tool_card(row, column, title, description, command):
    card = customtkinter.CTkFrame(tools_frame, fg_color="#0f1c2e", corner_radius=16)
    card.grid(row=row, column=column, padx=15, pady=15, sticky="nsew")
    name = customtkinter.CTkLabel(card, text=title, font=("Segoe UI", 18, "bold"))
    name.pack(anchor="w", padx=20, pady=(20, 10))
    desc = customtkinter.CTkLabel(card, text=description, justify="left")
    desc.pack(anchor="w", padx=20, pady=(0, 15))
    launch = customtkinter.CTkButton(card, text="Launch", command=command, height=36)
    launch.pack(padx=20, pady=(0, 20), anchor="w")


tool_definitions = [
    (
        "Web Scraping",
        "Harvest structured text, media, and metadata from static or dynamic pages.",
        scraping,
    ),
    (
        "ParamSpider",
        "Enumerate URL parameters, pace requests, and auto-tag XSS/SQLi/open-redirect vectors.",
        param_spider_tool,
    ),
    (
        "Vulnerability Scanner",
        "Replay payload lists, triage reflected output, and export scan notes per host.",
        vulnerability_scanner,
    ),
    (
        "Password Operations",
        "Generate, mutate, and crack passwords or hashes with dedicated helpers.",
        password_operations,
    ),
    (
        "Directory Scanner",
        "Bruteforce wordlists with adaptive delays to uncover hidden panels and APIs.",
        directory_scanner,
    ),
    (
        "Subdomain Finder",
        "Passively enumerate crt.sh, Sonar, and AlienVault datasets for scoped hosts.",
        subdomain_finder,
    ),
    (
        "Admin Finder",
        "Leverage mutable wordlists + Wayback URLs to lock onto admin dashboards.",
        adminpagesFinder,
    ),
    (
        "Technology Profiler",
        "Fingerprint versions, missing security headers, and exposed files per host.",
        technology_profiler,
    ),
    (
        "Web Data Workflows",
        "Scrape social/email/CVE intel from staged workflows with export support.",
        scraping_websites,
    ),
    (
        "JavaScript Intel",
        "Pull script inventories, URLs, and secrets directly from in-scope assets.",
        javascript_intel_tool,
    ),
    (
        "HTTP Probe",
        "Test domain lists for responsive HTTP/HTTPS stacks with rate controls.",
        http_probe_tool,
    ),
    (
        "Port Scanner",
        "Fan-out SYN/connect scans with custom port sets and exports.",
        port_scanner_tool,
    ),
]

for idx, tool in enumerate(tool_definitions):
    build_tool_card(idx // 3, idx % 3, *tool)


# About windows reuse historic content
def about_scraping_tool():
    scraping_window = customtkinter.CTkToplevel()
    customtkinter.set_appearance_mode("dark")
    customtkinter.set_default_color_theme("dark-blue")
    scraping_window.title("About Web Scraping Tool")
    scraping_window.geometry("1100x800")
    background_image = open_image("background1.jpg")
    background_image = background_image.resize(
        (scraping_window.winfo_screenwidth(), scraping_window.winfo_screenheight()),
        Image.BICUBIC,
    )
    background_image = ImageTk.PhotoImage(background_image)
    background_label = customtkinter.CTkLabel(scraping_window, image=background_image)
    background_label.image = background_image
    background_label.place(x=0, y=0, relwidth=1, relheight=1)
    about_label = customtkinter.CTkLabel(
        scraping_window,
        text="Web scraping, also known as data scraping, is the process of automatically extracting data from websites.\n"
        "This technique is used to collect large amounts of data from websites that would otherwise be time-consuming"
        " or difficult to extract manually.\n\n"
        "Web scraping can be done in various ways, including by using programming languages like Python or by"
        " using specialized tools like web scraping software.\nHere are some examples:\n"
        "1-) Price comparison websites aggregate prices, ratings, and reviews before presenting them side-by-side.\n"
        "2-) Social media analytics platforms extract engagement, sentiment, and other metrics for marketing.\n\n"
        "Always scrape ethically, respecting site terms and applicable laws.",
        font=("Courier", 16),
        fg_color="#0B1320",
    )
    about_label.pack(fill="both", expand=True)
    about_label.place(relx=0.5, rely=0.5, anchor=CENTER)
    back_button = customtkinter.CTkButton(scraping_window, text="Back", command=scraping_window.destroy)
    back_button.place(relx=0.5, rely=0.92, anchor=CENTER)


def about_params_spider():
    param_window = customtkinter.CTkToplevel()
    customtkinter.set_appearance_mode("dark")
    customtkinter.set_default_color_theme("dark-blue")
    param_window.title("About ParamSpider Tool")
    param_window.geometry("1100x800")
    background_image = open_image("background1.jpg")
    background_image = background_image.resize(
        (param_window.winfo_screenwidth(), param_window.winfo_screenheight()),
        Image.BICUBIC,
    )
    background_image = ImageTk.PhotoImage(background_image)
    background_label = customtkinter.CTkLabel(param_window, image=background_image)
    background_label.image = background_image
    background_label.place(x=0, y=0, relwidth=1, relheight=1)
    about_label = customtkinter.CTkLabel(
        param_window,
        text="Parameter Spider hunts parameters and injects payloads to highlight risky behaviors.\n"
        "Examples:\n"
        "1-) SQL Injection: send crafted SQL through input fields and query strings to surface raw DB errors.\n"
        "2-) XSS: inject scripts through parameters to identify reflected or stored vector points.\n\n"
        "Use findings responsibly and validate proofs before reporting.",
        font=("Courier", 16),
        fg_color="#0B1320",
    )
    about_label.pack(fill="both", expand=True)
    about_label.place(relx=0.5, rely=0.5, anchor=CENTER)
    back_button = customtkinter.CTkButton(param_window, text="Back", command=param_window.destroy)
    back_button.place(relx=0.5, rely=0.92, anchor=CENTER)


def about_vulnerability_scanner():
    scanner_window = customtkinter.CTkToplevel()
    customtkinter.set_appearance_mode("dark")
    customtkinter.set_default_color_theme("dark-blue")
    scanner_window.title("About Vulnerability Scanner")
    scanner_window.geometry("1100x850")
    background_image = open_image("background1.jpg")
    background_image = background_image.resize(
        (scanner_window.winfo_screenwidth(), scanner_window.winfo_screenheight()),
        Image.BICUBIC,
    )
    background_image = ImageTk.PhotoImage(background_image)
    background_label = customtkinter.CTkLabel(scanner_window, image=background_image)
    background_label.image = background_image
    background_label.place(x=0, y=0, relwidth=1, relheight=1)
    about_label = customtkinter.CTkLabel(
        scanner_window,
        text="Vulnerability scanners replay payloads to identify SQL injection, XSS, and related flaws.\n"
        "SQL injection attacks force databases to run attacker-controlled queries.\n"
        "XSS attacks inject scripts that run in other users' browsers, stealing data or hijacking sessions.\n\n"
        "Combine automated detection with manual validation before sharing findings with stakeholders.",
        font=("Courier", 16),
        fg_color="#0B1320",
    )
    about_label.pack(fill="both", expand=True)
    about_label.place(relx=0.5, rely=0.5, anchor=CENTER)
    back_button = customtkinter.CTkButton(scanner_window, text="Back", command=scanner_window.destroy)
    back_button.place(relx=0.5, rely=0.92, anchor=CENTER)


def about_password_operations():
    password_window = customtkinter.CTkToplevel()
    customtkinter.set_appearance_mode("dark")
    customtkinter.set_default_color_theme("dark-blue")
    password_window.title("About Password Operations")
    password_window.geometry("1100x850")
    background_image = open_image("background1.jpg")
    background_image = background_image.resize(
        (password_window.winfo_screenwidth(), password_window.winfo_screenheight()),
        Image.BICUBIC,
    )
    background_image = ImageTk.PhotoImage(background_image)
    background_label = customtkinter.CTkLabel(password_window, image=background_image)
    background_label.image = background_image
    background_label.place(x=0, y=0, relwidth=1, relheight=1)
    about_label = customtkinter.CTkLabel(
        password_window,
        text="Password Operations bundles generators and hash crackers.\n"
        "• Hash crackers brute-force original plaintext from hashed values to test password resilience.\n"
        "• Generators create long, unique credentials with selectable character sets.\n\n"
        "These helpers streamline credential hygiene during engagements.",
        font=("Courier", 16),
        fg_color="#0B1320",
    )
    about_label.pack(fill="both", expand=True)
    about_label.place(relx=0.5, rely=0.5, anchor=CENTER)
    back_button = customtkinter.CTkButton(password_window, text="Back", command=password_window.destroy)
    back_button.place(relx=0.5, rely=0.92, anchor=CENTER)


learn_more_frame = customtkinter.CTkFrame(root, fg_color="#0f1c2e", corner_radius=18)
learn_more_frame.pack(fill="x", padx=30, pady=(0, 25))
learn_more_label = customtkinter.CTkLabel(
    learn_more_frame,
    text="Need more context?",
    font=("Segoe UI", 16, "bold"),
)
learn_more_label.grid(row=0, column=0, padx=20, pady=15, sticky="w")

about_buttons = [
    ("About Scraping", about_scraping_tool),
    ("About ParamSpider", about_params_spider),
    ("About Vuln Scanner", about_vulnerability_scanner),
    ("About Password Ops", about_password_operations),
]

for idx, (label, command) in enumerate(about_buttons, start=1):
    btn = customtkinter.CTkButton(learn_more_frame, text=label, command=command)
    btn.grid(row=0, column=idx, padx=10, pady=15)


root.mainloop()
