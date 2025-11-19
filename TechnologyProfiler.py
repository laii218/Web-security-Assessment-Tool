import threading
import time
from tkinter import messagebox

import customtkinter as ctk

from fingerprinting import export_fingerprints, fingerprint_url
from session_state import get_target, is_url_in_scope


REQUEST_TIMEOUT = 8.0


def technology_profiler():
    window = ctk.CTkToplevel()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    window.title("Technology & Version Profiler")
    window.geometry("1100x720")

    main_frame = ctk.CTkFrame(window, fg_color="#0d1321", corner_radius=16)
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)

    header = ctk.CTkLabel(
        main_frame,
        text=(
            "Profile technologies, versions, and exposed assets for every scoped target.\n"
            "Results highlight missing security headers, certificate metadata, and interesting files."
        ),
        justify="left",
        font=("Segoe UI", 16),
    )
    header.pack(anchor="w", padx=20, pady=(20, 10))

    controls = ctk.CTkFrame(main_frame, fg_color="#111b2c", corner_radius=14)
    controls.pack(fill="x", padx=20, pady=10)

    target_var = ctk.StringVar(value=get_target())
    target_entry = ctk.CTkEntry(controls, width=320, textvariable=target_var)
    target_entry.grid(row=0, column=0, padx=10, pady=10, sticky="w")

    def sync_target():
        target = get_target()
        if not target:
            messagebox.showinfo("Global Target", "Define a global target in the main window first.")
            return
        target_var.set(target)

    global_button = ctk.CTkButton(controls, text="Use Global Target", command=sync_target)
    global_button.grid(row=0, column=1, padx=10, pady=10)

    scope_hint = ctk.CTkLabel(
        controls,
        text="Only scoped hosts will be scanned. Add additional URLs (one per line) below.",
        justify="left",
    )
    scope_hint.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 5), sticky="w")

    list_frame = ctk.CTkFrame(main_frame, fg_color="#111b2c", corner_radius=14)
    list_frame.pack(fill="both", expand=False, padx=20, pady=10)

    extra_label = ctk.CTkLabel(list_frame, text="Extra URLs / Paths:")
    extra_label.grid(row=0, column=0, padx=10, pady=10, sticky="nw")
    extra_box = ctk.CTkTextbox(list_frame, width=420, height=120)
    extra_box.grid(row=0, column=1, padx=10, pady=10)

    options_frame = ctk.CTkFrame(main_frame, fg_color="#111b2c", corner_radius=14)
    options_frame.pack(fill="x", padx=20, pady=10)

    include_interesting_var = ctk.BooleanVar(value=True)
    include_check = ctk.CTkCheckBox(
        options_frame,
        text="Probe common sensitive files (robots.txt, .git/HEAD, server-status, etc.)",
        variable=include_interesting_var,
    )
    include_check.grid(row=0, column=0, padx=10, pady=10, sticky="w")

    delay_var = ctk.DoubleVar(value=0.5)
    delay_label = ctk.CTkLabel(options_frame, text="Request Delay (seconds):")
    delay_label.grid(row=1, column=0, padx=10, pady=(0, 5), sticky="w")
    delay_slider = ctk.CTkSlider(options_frame, from_=0, to=5, number_of_steps=20, variable=delay_var)
    delay_slider.grid(row=1, column=1, padx=10, pady=(0, 5), sticky="ew")
    options_frame.grid_columnconfigure(1, weight=1)

    export_button = ctk.CTkButton(options_frame, text="Export last run", state="disabled")
    export_button.grid(row=0, column=1, padx=10, pady=10)

    output_box = ctk.CTkTextbox(main_frame, width=900, height=360)
    output_box.pack(fill="both", expand=True, padx=20, pady=10)

    status_label = ctk.CTkLabel(main_frame, text="Idle", font=("Segoe UI", 14))
    status_label.pack(anchor="w", padx=25, pady=(0, 10))

    last_results = []

    def append(message: str):
        output_box.insert("end", message)
        output_box.insert("end", "\n" if not message.endswith("\n") else "")
        output_box.see("end")

    def run_scan():
        base = target_var.get().strip()
        extras = [line.strip() for line in extra_box.get("1.0", "end").splitlines() if line.strip()]
        targets = []
        if base:
            targets.append(base)
        targets.extend(extras)
        seen = []
        for url in targets:
            if url not in seen:
                seen.append(url)
        if not seen:
            messagebox.showerror("Targets", "Provide at least one URL to profile.")
            return

        output_box.delete("1.0", "end")
        status_label.configure(text="Running fingerprint sweep...")
        export_button.configure(state="disabled")

        def worker():
            nonlocal last_results
            collected = []
            for idx, target in enumerate(seen, 1):
                if not is_url_in_scope(target):
                    append(f"[!] Skipping {target} because it is outside of scope.")
                    continue
                append(f"[*] Profiling {target} ({idx}/{len(seen)})...")
                fingerprint = fingerprint_url(
                    target,
                    timeout=REQUEST_TIMEOUT,
                    include_interesting=include_interesting_var.get(),
                )
                collected.append(fingerprint)
                append(fingerprint.to_report())
                delay = delay_var.get()
                if delay:
                    time.sleep(delay)
            if not collected:
                append("No in-scope targets were profiled.")
            last_results = collected

            def finalize():
                status_label.configure(text="Completed fingerprint sweep.")
                if collected:
                    export_button.configure(state="normal")

            window.after(0, finalize)

        threading.Thread(target=worker, daemon=True).start()

    run_button = ctk.CTkButton(main_frame, text="Start Profiling", command=run_scan, height=40)
    run_button.pack(pady=10)

    def export_results():
        if not last_results:
            messagebox.showinfo("Export", "Run a scan first.")
            return
        data = export_fingerprints(last_results)
        try:
            from tkinter import filedialog

            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON", "*.json"), ("All Files", "*.*")],
            )
            if not file_path:
                return
            with open(file_path, "w", encoding="utf-8") as fh:
                fh.write(data)
            messagebox.showinfo("Export", f"Saved {len(last_results)} fingerprints to {file_path}")
        except OSError as exc:
            messagebox.showerror("Export", f"Failed to write file: {exc}")

    export_button.configure(command=export_results)
