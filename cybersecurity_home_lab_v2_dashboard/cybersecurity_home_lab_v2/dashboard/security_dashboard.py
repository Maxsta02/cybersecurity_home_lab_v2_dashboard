import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import re

LOG_RE = re.compile(
    r"^(?P<timestamp>\S+\s+\S+)\s+"
    r"(?P<event>LOGIN_(?:FAILED|SUCCESS))\s+"
    r"user=(?P<user>\S+)\s+ip=(?P<ip>\S+)$"
)
FAILURE_THRESHOLD = 5
WINDOW_MINUTES = 5

DEFAULT_LOG = Path(__file__).resolve().parents[1] / "data" / "auth.log"

def parse_log(path):
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            m = LOG_RE.match(line.strip())
            if not m:
                continue
            events.append({
                "timestamp": datetime.strptime(m["timestamp"], "%Y-%m-%d %H:%M:%S"),
                "event": m["event"],
                "user": m["user"],
                "ip": m["ip"],
                "line": line_no,
            })
    return events

def analyse(events):
    failures = [e for e in events if e["event"] == "LOGIN_FAILED"]
    successes = [e for e in events if e["event"] == "LOGIN_SUCCESS"]
    ip_counts = Counter(e["ip"] for e in failures)
    user_counts = Counter(e["user"] for e in failures)
    alerts = []

    by_ip = defaultdict(list)
    for e in failures:
        by_ip[e["ip"]].append(e)

    for ip, rows in by_ip.items():
        rows.sort(key=lambda x: x["timestamp"])
        for i, start in enumerate(rows):
            window = [x for x in rows[i:] if x["timestamp"] <= start["timestamp"] + timedelta(minutes=WINDOW_MINUTES)]
            if len(window) >= FAILURE_THRESHOLD:
                alerts.append({
                    "type": "POTENTIAL BRUTE FORCE",
                    "severity": "HIGH",
                    "ip": ip,
                    "count": len(window),
                    "users": sorted({x["user"] for x in window}),
                    "detail": f"{len(window)} failed logins within {WINDOW_MINUTES} minutes"
                })
                break

    for success in successes:
        prior = [
            x for x in failures
            if x["ip"] == success["ip"]
            and 0 <= (success["timestamp"] - x["timestamp"]).total_seconds() <= 600
        ]
        if len(prior) >= 3:
            alerts.append({
                "type": "SUCCESS AFTER FAILURES",
                "severity": "MEDIUM",
                "ip": success["ip"],
                "count": len(prior),
                "users": [success["user"]],
                "detail": f"Successful login after {len(prior)} failures"
            })

    unique = {}
    for a in alerts:
        unique[(a["type"], a["ip"])] = a
    return failures, successes, ip_counts, user_counts, list(unique.values())

class SecurityDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Security Monitoring Dashboard")
        self.geometry("1100x700")
        self.minsize(950, 600)
        self.configure(bg="#10151c")
        self.events = []
        self.alerts = []
        self._style()
        self._build()
        self.load_log(DEFAULT_LOG)

    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TFrame", background="#10151c")
        s.configure("Card.TFrame", background="#18212b")
        s.configure("TLabel", background="#10151c", foreground="#e7edf4", font=("Segoe UI", 10))
        s.configure("Title.TLabel", background="#10151c", foreground="#ffffff", font=("Segoe UI", 22, "bold"))
        s.configure("Sub.TLabel", background="#10151c", foreground="#9fb0c0", font=("Segoe UI", 10))
        s.configure("CardTitle.TLabel", background="#18212b", foreground="#aebdca", font=("Segoe UI", 9, "bold"))
        s.configure("Metric.TLabel", background="#18212b", foreground="#ffffff", font=("Segoe UI", 21, "bold"))
        s.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        s.configure("Treeview", background="#18212b", fieldbackground="#18212b", foreground="#e7edf4", rowheight=28)
        s.configure("Treeview.Heading", background="#24313d", foreground="#ffffff", font=("Segoe UI", 9, "bold"))

    def _build(self):
        outer = ttk.Frame(self, padding=24)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="SECURITY MONITORING DASHBOARD", style="Title.TLabel").pack(side="left")
        ttk.Button(header, text="Load Log File", command=self.choose_file).pack(side="right")

        self.status = ttk.Label(outer, text="Controlled lab / synthetic data", style="Sub.TLabel")
        self.status.pack(anchor="w", pady=(4, 18))

        cards = ttk.Frame(outer)
        cards.pack(fill="x")
        self.metrics = {}
        for name in ["EVENTS", "FAILED LOGINS", "SUCCESSFUL LOGINS", "ALERTS", "SUSPICIOUS IPS"]:
            card = ttk.Frame(cards, style="Card.TFrame", padding=16)
            card.pack(side="left", fill="x", expand=True, padx=(0, 10))
            ttk.Label(card, text=name, style="CardTitle.TLabel").pack(anchor="w")
            label = ttk.Label(card, text="0", style="Metric.TLabel")
            label.pack(anchor="w", pady=(5, 0))
            self.metrics[name] = label

        body = ttk.Frame(outer)
        body.pack(fill="both", expand=True, pady=(20, 0))

        left = ttk.Frame(body, style="Card.TFrame", padding=16)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        ttk.Label(left, text="SECURITY ALERTS", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 10))

        columns = ("severity", "type", "ip", "count", "detail")
        self.tree = ttk.Treeview(left, columns=columns, show="headings")
        headings = {"severity":"SEVERITY","type":"DETECTION","ip":"SOURCE IP","count":"EVENTS","detail":"DETAIL"}
        widths = {"severity":85,"type":180,"ip":125,"count":70,"detail":330}
        for c in columns:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.tag_configure("HIGH", foreground="#ff7b72")
        self.tree.tag_configure("MEDIUM", foreground="#f2cc60")
        self.tree.pack(fill="both", expand=True)

        right = ttk.Frame(body, style="Card.TFrame", padding=16)
        right.pack(side="right", fill="y")
        ttk.Label(right, text="FAILED LOGINS BY SOURCE", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 10))
        self.ip_text = tk.Text(right, width=32, height=10, bg="#18212b", fg="#dbe7f2",
                               insertbackground="white", relief="flat", font=("Consolas", 10))
        self.ip_text.pack(fill="x")

        ttk.Label(right, text="TARGETED ACCOUNTS", style="CardTitle.TLabel").pack(anchor="w", pady=(20, 10))
        self.user_text = tk.Text(right, width=32, height=10, bg="#18212b", fg="#dbe7f2",
                                 insertbackground="white", relief="flat", font=("Consolas", 10))
        self.user_text.pack(fill="x")

        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(14, 0))
        self.file_label = ttk.Label(footer, text="No file loaded", style="Sub.TLabel")
        self.file_label.pack(side="left")
        ttk.Button(footer, text="Refresh Analysis", command=self.refresh).pack(side="right")

    def choose_file(self):
        path = filedialog.askopenfilename(title="Select authentication log",
                                          filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.load_log(Path(path))

    def load_log(self, path):
        try:
            self.events = parse_log(path)
            if not self.events:
                raise ValueError("No recognised authentication events were found.")
            self.path = path
            self.refresh()
            self.status.config(text=f"Analysing: {path.name}  |  Controlled / authorised data only")
        except Exception as e:
            messagebox.showerror("Unable to analyse log", str(e))

    def refresh(self):
        if not self.events:
            return
        failures, successes, ip_counts, user_counts, alerts = analyse(self.events)
        self.alerts = alerts
        suspicious = {a["ip"] for a in alerts}
        values = {
            "EVENTS": len(self.events),
            "FAILED LOGINS": len(failures),
            "SUCCESSFUL LOGINS": len(successes),
            "ALERTS": len(alerts),
            "SUSPICIOUS IPS": len(suspicious)
        }
        for k, v in values.items():
            self.metrics[k].config(text=str(v))

        for item in self.tree.get_children():
            self.tree.delete(item)
        for a in alerts:
            self.tree.insert("", "end",
                values=(a["severity"], a["type"], a["ip"], a["count"], a["detail"]),
                tags=(a["severity"],))

        self.ip_text.delete("1.0", "end")
        for ip, count in ip_counts.most_common():
            self.ip_text.insert("end", f"{ip:<18} {count:>4}\n")

        self.user_text.delete("1.0", "end")
        for user, count in user_counts.most_common():
            self.user_text.insert("end", f"{user:<18} {count:>4}\n")

        self.file_label.config(text=f"Log: {self.path}")

if __name__ == "__main__":
    SecurityDashboard().mainloop()
