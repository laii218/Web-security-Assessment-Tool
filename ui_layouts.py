"""Reusable layout primitives for customtkinter tool windows."""
from __future__ import annotations

from typing import Callable, Optional, Tuple

import tkinter as tk
import customtkinter as ctk

PRIMARY_BG = "#050c18"
CARD_BG = "#0f1c2e"
HEADER_BG = "#081224"
TEXT_MUTED = "#8EA4C0"
TEXT_DEFAULT = "#E2E8F0"


def _init_theme() -> None:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")


def create_tool_window(title: str, size: Tuple[int, int] = (1200, 820)) -> ctk.CTkToplevel:
    """Return a consistently styled tool window."""
    _init_theme()
    width, height = size
    window = ctk.CTkToplevel()
    window.title(title)
    window.geometry(f"{width}x{height}")
    window.configure(fg_color=PRIMARY_BG)
    window.grid_columnconfigure(0, weight=1)
    window.grid_rowconfigure(1, weight=1)
    return window


def build_header(parent, title: str, subtitle: str) -> ctk.CTkFrame:
    header = ctk.CTkFrame(parent, fg_color=HEADER_BG, corner_radius=22)
    header.grid(row=0, column=0, sticky="ew", padx=30, pady=(25, 12))
    title_label = ctk.CTkLabel(header, text=title, font=("Segoe UI", 28, "bold"))
    title_label.pack(anchor="w", padx=26, pady=(24, 8))
    subtitle_label = ctk.CTkLabel(
        header,
        text=subtitle,
        font=("Segoe UI", 16),
        justify="left",
        text_color=TEXT_MUTED,
    )
    subtitle_label.pack(anchor="w", padx=26, pady=(0, 22))
    return header


def build_content(parent, columns: int = 2) -> ctk.CTkFrame:
    content = ctk.CTkFrame(parent, fg_color=PRIMARY_BG)
    content.grid(row=1, column=0, sticky="nsew", padx=30, pady=(0, 18))
    for column in range(columns):
        content.grid_columnconfigure(column, weight=1, uniform="content")
    content.grid_rowconfigure(0, weight=1)
    return content


def build_section_card(parent, title: str, description: Optional[str] = None) -> ctk.CTkFrame:
    frame = ctk.CTkFrame(parent, fg_color=CARD_BG, corner_radius=20)
    title_label = ctk.CTkLabel(frame, text=title, font=("Segoe UI", 20, "bold"))
    title_label.pack(anchor="w", padx=22, pady=(20, 4))
    if description:
        desc_label = ctk.CTkLabel(
            frame,
            text=description,
            text_color=TEXT_MUTED,
            justify="left",
            font=("Segoe UI", 13),
        )
        desc_label.pack(anchor="w", padx=22, pady=(0, 10))
    return frame


def build_log_panel(
    parent,
    title: str = "Activity log",
) -> tuple[ctk.CTkFrame, tk.Text, Callable[[str], None], Callable[[], None]]:
    frame = build_section_card(parent, title)
    text_widget = tk.Text(
        frame,
        bg="#020712",
        fg=TEXT_DEFAULT,
        insertbackground=TEXT_DEFAULT,
        wrap=tk.WORD,
        relief="flat",
        height=20,
        borderwidth=0,
        font=("Consolas", 12),
    )
    scrollbar = tk.Scrollbar(frame, command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    text_widget.pack(side="left", fill="both", expand=True, padx=(22, 0), pady=(0, 22))
    scrollbar.pack(side="right", fill="y", padx=(0, 22), pady=(0, 22))

    def log(message: str) -> None:
        text_widget.insert(tk.END, message + "
")
        text_widget.see(tk.END)

    def clear() -> None:
        text_widget.delete("1.0", tk.END)

    return frame, text_widget, log, clear


def build_status_bar(
    parent,
    status_var: tk.StringVar,
    scope_var: Optional[tk.StringVar] = None,
) -> tuple[ctk.CTkFrame, ctk.CTkLabel]:
    bar = ctk.CTkFrame(parent, fg_color=HEADER_BG, corner_radius=16)
    bar.grid(row=2, column=0, sticky="ew", padx=30, pady=(0, 25))
    status_label = ctk.CTkLabel(bar, textvariable=status_var, font=("Segoe UI", 15))
    status_label.pack(side="left", padx=24, pady=14)
    if scope_var is None:
        scope_var = tk.StringVar(value="")
    scope_label = ctk.CTkLabel(bar, textvariable=scope_var, font=("Segoe UI", 13), text_color=TEXT_MUTED)
    scope_label.pack(side="right", padx=24)
    return bar, scope_label


def build_button_row(parent) -> ctk.CTkFrame:
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", padx=22, pady=(6, 16))
    row.pack_propagate(False)
    return row


def attach_modal_behavior(window: ctk.CTkToplevel) -> None:
    """Give the tool window focus without blocking the root app."""
    window.transient()
    window.focus()
    try:
        window.grab_set()
    except tk.TclError:
        # Fallback for environments that do not support grabs
        pass
