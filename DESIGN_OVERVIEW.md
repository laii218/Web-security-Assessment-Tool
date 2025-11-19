# Application Layout Overview

The Tkinter dashboard defined in `main.py` was rebuilt around three primary sections:

1. **Hero Banner (`build_banner`)** – a full-width header panel with the "Web Security Assessment HQ" title and guidance subtitle implemented via `customtkinter.CTkFrame` and `CTkLabel` widgets (see `main.py`, lines 32-44).
2. **Global Target & Scope Card** – the `target_scope_frame` block (lines 49-92) lets every tool share a single target/ scope combination, including persistent status labels and multiline scope editing.
3. **Operational Guidance Panel** – a second callout frame (lines 98-106) delivers concise rules of engagement to reinforce methodology before scanning.
4. **Card-Based Launcher Grid** – a scrollable frame (`tools_frame`, lines 111-161) renders modern tool cards with names, descriptions, and launch buttons for each module, including the newly added Admin Finder and Technology Profiler cards.

Together these upgrades give the application a structured, modernized design compared to the previous button list, pairing consistent color palettes (`fg_color` assignments) and typography (Segoe UI variants) across every major region.
