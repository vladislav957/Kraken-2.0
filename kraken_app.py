#!/usr/bin/env python3
"""
kraken_app.py — Kraken Audit desktop application (the GUI software).

A native desktop window (Tkinter, standard library — no browser, no
dependencies) built on top of kraken_core. Point it at your own nodes, run the
read-only audits with a click, and read the findings with a Security Score at
the top.

    python3 kraken_app.py

If it reports that Tk is missing, install your distro's Tk package
(e.g. `sudo apt install python3-tk`).
"""

from __future__ import annotations

import queue
import threading

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext
except ImportError:                                   # headless / no Tk
    raise SystemExit(
        "Tkinter is not available. Install it (e.g. 'sudo apt install "
        "python3-tk') and run again. For a no-GUI run use the CLI tools or "
        "kraken_core directly.")

import kraken_core as core
import audit_common as ac

# ---- palette ----
BG = "#0f131c"; PANEL = "#171d2a"; FG = "#e9eef7"; MUTED = "#95a3b6"
ACCENT = "#46d39a"
SEV = {"CRITICAL": "#ff5468", "HIGH": "#ff914d", "MEDIUM": "#ffd23f",
       "LOW": "#56a8ff", "INFO": "#8d9bb0", "OK": "#46d39a"}


class KrakenApp:
    def __init__(self, root: "tk.Tk"):
        self.root = root
        self.results = {"node": None, "lightning": None, "miner": None,
                        "exposure": None}
        self.ui_queue: "queue.Queue" = queue.Queue()

        root.title("Kraken Audit")
        root.geometry("900x720")
        root.minsize(680, 560)
        root.configure(bg=BG)
        self._init_style()
        self._build_header()
        self._build_score()
        self._build_tabs()
        self.root.after(80, self._drain_queue)

    # ---- styling ----
    def _init_style(self):
        st = ttk.Style(self.root)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=FG, fieldbackground=PANEL,
                     bordercolor="#2a3448", font=("TkDefaultFont", 10))
        st.configure("TNotebook", background=BG, borderwidth=0)
        st.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                     padding=(14, 7))
        st.map("TNotebook.Tab", background=[("selected", BG)],
               foreground=[("selected", FG)])
        st.configure("TFrame", background=BG)
        st.configure("TLabel", background=BG, foreground=FG)
        st.configure("Muted.TLabel", foreground=MUTED)
        st.configure("TCheckbutton", background=BG, foreground=MUTED)
        st.map("TCheckbutton", background=[("active", BG)])
        st.configure("Run.TButton", background=ACCENT, foreground="#06101a",
                     font=("TkDefaultFont", 10, "bold"), borderwidth=0, padding=(14, 7))
        st.map("Run.TButton", background=[("active", "#3bc08a"), ("disabled", "#2a3448")])
        st.configure("TEntry", fieldbackground=PANEL, foreground=FG, insertcolor=FG)
        st.configure("TCombobox", fieldbackground=PANEL, foreground=FG)

    def _build_header(self):
        f = ttk.Frame(self.root); f.pack(fill="x", padx=16, pady=(14, 0))
        ttk.Label(f, text="Kraken Audit", font=("TkDefaultFont", 17, "bold")).pack(anchor="w")
        ttk.Label(f, style="Muted.TLabel",
                  text="Desktop GUI for the read-only auditors — point it at your "
                       "own nodes and harden what lights up.").pack(anchor="w")

    # ---- score widget ----
    def _build_score(self):
        self.score_frame = tk.Frame(self.root, bg=PANEL, highlightthickness=1,
                                    highlightbackground="#2a3448")
        self.score_frame.pack(fill="x", padx=16, pady=14)
        self.ring = tk.Label(self.score_frame, text="–", width=4, height=2,
                             font=("TkDefaultFont", 15, "bold"),
                             bg="#2a3344", fg=MUTED)
        self.ring.pack(side="left", padx=14, pady=12)
        box = tk.Frame(self.score_frame, bg=PANEL); box.pack(side="left", pady=12)
        tk.Label(box, text="SECURITY SCORE", bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", 8)).pack(anchor="w")
        self.score_label = tk.Label(box, text="No audit run yet", bg=PANEL, fg=FG,
                                    font=("TkDefaultFont", 14, "bold"))
        self.score_label.pack(anchor="w")
        self.chips = tk.Frame(self.score_frame, bg=PANEL)
        self.chips.pack(side="right", padx=14)
        self._render_chips(core.overall([]))

    def _render_chips(self, score):
        for w in self.chips.winfo_children():
            w.destroy()
        for sev in core.SEVERITY_ORDER:
            n = score.totals.get(sev, 0)
            bg = SEV[sev] if n else "#222a39"
            fg = "#06101a" if n else MUTED
            tk.Label(self.chips, text=f"{sev[0]} {n}", bg=bg, fg=fg, padx=7, pady=2,
                     font=("TkDefaultFont", 9, "bold")).pack(side="left", padx=3)

    def _update_score(self):
        score = core.overall([r for r in self.results.values() if r])
        self._render_chips(score)
        if score.label == "No audit run yet":
            self.ring.config(text="–", bg="#2a3344", fg=MUTED)
            self.score_label.config(text="No audit run yet")
            return
        color = SEV[score.worst]
        self.ring.config(text=f"{score.score}", bg=color, fg="#06101a")
        self.score_label.config(text=f"{score.label}  ·  {score.score}/100 ({score.grade})")

    # ---- tabs ----
    def _build_tabs(self):
        nb = ttk.Notebook(self.root); nb.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.nb = nb
        self.outputs = {}
        self.inputs = {}

        # Bitcoin Core
        t = ttk.Frame(nb); nb.add(t, text="  Bitcoin Core  ")
        row = ttk.Frame(t); row.pack(fill="x", padx=12, pady=10)
        ttk.Label(row, text="bitcoin.conf (blank = auto):", style="Muted.TLabel").pack(side="left")
        e = ttk.Entry(row); e.pack(side="left", fill="x", expand=True, padx=8)
        sock = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="sockets", variable=sock).pack(side="left", padx=6)
        ttk.Button(row, text="Run audit", style="Run.TButton",
                   command=lambda: self._run("node")).pack(side="left")
        self.inputs["node"] = {"conf": e, "sockets": sock}
        self.outputs["node"] = self._findings_box(t)

        # Lightning
        t = ttk.Frame(nb); nb.add(t, text="  Lightning  ")
        row = ttk.Frame(t); row.pack(fill="x", padx=12, pady=10)
        impl = ttk.Combobox(row, values=["auto", "lnd", "cln"], width=6, state="readonly")
        impl.set("auto"); impl.pack(side="left")
        conf = ttk.Entry(row); conf.pack(side="left", fill="x", expand=True, padx=6)
        conf.insert(0, ""); self._placeholder(conf, "lnd.conf / CLN config")
        ndir = ttk.Entry(row, width=16); ndir.pack(side="left", padx=4)
        self._placeholder(ndir, "~/.lnd")
        sock = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="sockets", variable=sock).pack(side="left", padx=6)
        ttk.Button(row, text="Run audit", style="Run.TButton",
                   command=lambda: self._run("lightning")).pack(side="left")
        self.inputs["lightning"] = {"impl": impl, "conf": conf, "dir": ndir, "sockets": sock}
        self.outputs["lightning"] = self._findings_box(t)

        # Miner
        t = ttk.Frame(nb); nb.add(t, text="  Miner  ")
        row = ttk.Frame(t); row.pack(fill="x", padx=12, pady=10)
        ttk.Label(row, text="host (one address):", style="Muted.TLabel").pack(side="left")
        tgt = ttk.Entry(row); tgt.pack(side="left", fill="x", expand=True, padx=6)
        self._placeholder(tgt, "192.168.1.50")
        port = ttk.Entry(row, width=7); port.pack(side="left"); port.insert(0, "4028")
        web = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="web", variable=web).pack(side="left", padx=6)
        ttk.Button(row, text="Run audit", style="Run.TButton",
                   command=lambda: self._run("miner")).pack(side="left")
        self.inputs["miner"] = {"target": tgt, "port": port, "web": web}
        self.outputs["miner"] = self._findings_box(t)

        # Exposure (local only)
        t = ttk.Frame(nb); nb.add(t, text="  Exposure  ")
        row = ttk.Frame(t); row.pack(fill="x", padx=12, pady=10)
        ttk.Label(row, text="What of THIS host is reachable off-box (local sockets only):",
                  style="Muted.TLabel").pack(side="left")
        ttk.Button(row, text="Run audit", style="Run.TButton",
                   command=lambda: self._run("exposure")).pack(side="left", padx=8)
        self.inputs["exposure"] = {}
        self.outputs["exposure"] = self._findings_box(t)

    def _findings_box(self, parent):
        box = scrolledtext.ScrolledText(parent, bg="#0c0f16", fg=FG, bd=0,
                                        insertbackground=FG, wrap="word",
                                        font=("TkFixedFont", 10), height=18,
                                        padx=10, pady=8, state="disabled")
        box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        for sev, col in SEV.items():
            box.tag_config(sev, foreground=col, font=("TkFixedFont", 10, "bold"))
        box.tag_config("muted", foreground=MUTED)
        box.tag_config("fix", foreground=ACCENT)
        box.tag_config("title", foreground=FG, font=("TkFixedFont", 10, "bold"))
        return box

    def _placeholder(self, entry, text):
        entry.insert(0, text)
        entry.config(foreground=MUTED)
        def on_in(_):
            if entry.get() == text:
                entry.delete(0, "end"); entry.config(foreground=FG)
        def on_out(_):
            if not entry.get():
                entry.insert(0, text); entry.config(foreground=MUTED)
        entry.bind("<FocusIn>", on_in); entry.bind("<FocusOut>", on_out)
        entry._ph = text

    def _val(self, entry):
        v = entry.get().strip()
        return "" if v == getattr(entry, "_ph", None) else v

    # ---- run (threaded) ----
    def _run(self, tool):
        box = self.outputs[tool]
        self._write(box, [("Running audit…\n", "muted")])
        inp = self.inputs[tool]

        # Read all widget values on the MAIN thread; the worker only touches the
        # pure engine (Tk is not thread-safe).
        if tool == "node":
            params = {"conf": self._val(inp["conf"]), "sockets": inp["sockets"].get()}
        elif tool == "lightning":
            params = {"impl": inp["impl"].get(), "conf": self._val(inp["conf"]),
                      "dir": self._val(inp["dir"]), "sockets": inp["sockets"].get()}
        elif tool == "miner":
            try:
                port = int(self._val(inp["port"]) or 4028)
            except ValueError:
                port = 4028
            params = {"target": self._val(inp["target"]), "port": port,
                      "web": inp["web"].get()}
        else:
            params = {}

        def work():
            try:
                if tool == "node":
                    res = core.audit_node(params["conf"], params["sockets"])
                elif tool == "lightning":
                    res = core.audit_lightning(params["impl"], params["conf"],
                                               params["dir"], params["sockets"])
                elif tool == "exposure":
                    res = core.audit_exposure()
                else:
                    if not params["target"]:
                        raise ValueError("Enter a single miner host you own.")
                    res = core.audit_miner(params["target"], params["port"], params["web"])
                self.ui_queue.put((tool, res, None))
            except ac.TargetError as e:
                self.ui_queue.put((tool, None, str(e)))
            except Exception as e:                       # keep the app alive
                self.ui_queue.put((tool, None, f"{type(e).__name__}: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def _drain_queue(self):
        try:
            while True:
                tool, res, err = self.ui_queue.get_nowait()
                self._show(tool, res, err)
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)

    def _show(self, tool, res, err):
        box = self.outputs[tool]
        if err:
            self._write(box, [(err + "\n", "CRITICAL")])
            return
        self.results[tool] = res
        segs = [("  ·  ".join(f"{k}: {v}" for k, v in res.meta.items())
                 + f"  ·  exit {res.exit_code}\n\n", "muted")]
        if not res.findings:
            segs.append(("no findings\n", "muted"))
        for f in res.findings:
            segs.append((f"[{f.severity}] ", f.severity))
            segs.append((f.title + "\n", "title"))
            segs.append(("    " + f.detail + "\n", "muted"))
            if f.remediation:
                segs.append(("    Fix: ", "fix"))
                segs.append((f.remediation + "\n", "muted"))
            segs.append(("\n", "muted"))
        self._write(box, segs)
        self._update_score()

    def _write(self, box, segments):
        box.config(state="normal"); box.delete("1.0", "end")
        for text, tag in segments:
            box.insert("end", text, tag)
        box.config(state="disabled")


def main():
    root = tk.Tk()
    KrakenApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
