import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import secrets
import string
import re
import json
import os
import math
import hashlib
from datetime import datetime

# ============================================================
# OPTIONAL SECURITY LIBRARIES
# ============================================================

try:
    import pyotp
    import qrcode
    from PIL import Image, ImageTk
    SECURITY_LIBRARIES = True
except ImportError:
    SECURITY_LIBRARIES = False


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

APP_NAME = "SECUREPASS X"
APP_VERSION = "3.0"
HISTORY_FILE = "securepass_x_history.json"
QR_FILE = "securepass_x_totp_qr.png"

BG = "#0b1120"
PANEL = "#111827"
PANEL2 = "#172033"
CARD = "#1a2538"
BORDER = "#263449"

TEXT = "#f8fafc"
MUTED = "#94a3b8"

BLUE = "#38bdf8"
CYAN = "#22d3ee"
GREEN = "#34d399"
YELLOW = "#fbbf24"
ORANGE = "#fb923c"
RED = "#f87171"
PURPLE = "#a78bfa"

FONT = "Segoe UI"


# ============================================================
# SECURITY DATA
# ============================================================

COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "12345",
    "password",
    "password1",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "abc123",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "login",
    "pass123",
    "pass1234",
    "root",
    "test",
    "guest",
    "india123",
}

KEYBOARD_PATTERNS = [
    "qwerty",
    "asdf",
    "zxcv",
    "qwertyuiop",
    "asdfgh",
    "zxcvbn",
    "123456",
    "654321",
]

SEQUENCES = [
    "123",
    "234",
    "345",
    "456",
    "567",
    "678",
    "789",
    "abc",
    "bcd",
    "cde",
    "xyz",
]

PERSONAL_PATTERNS = [
    "admin",
    "user",
    "name",
    "password",
    "welcome",
    "college",
    "student",
    "india",
    "instagram",
    "gmail",
]

ACCOUNT_RISK = {
    "Instagram": 70,
    "Gmail": 90,
    "PhonePe": 95,
    "Banking": 100,
    "Gaming": 55,
    "College Portal": 65,
    "Social Media": 70,
    "Other": 60,
}


# ============================================================
# FILE FUNCTIONS
# ============================================================

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, list) else []

    except Exception:
        return []


def save_history(history):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as file:
            json.dump(history, file, indent=4)
        return True
    except Exception:
        return False


# ============================================================
# SECURITY ENGINE
# ============================================================

def calculate_entropy(password):
    if not password:
        return 0.0

    pool = 0

    if re.search(r"[a-z]", password):
        pool += 26

    if re.search(r"[A-Z]", password):
        pool += 26

    if re.search(r"\d", password):
        pool += 10

    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32

    if pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


def credential_fingerprint(password):
    """
    Demonstration-only identifier.
    The plaintext password is never saved.
    """
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return digest[:16].upper()


def analyze_password(password):
    score = 0
    findings = []
    recommendations = []

    if not password:
        return {
            "score": 0,
            "label": "NO CREDENTIAL",
            "entropy": 0,
            "findings": ["No credential supplied."],
            "recommendations": ["Enter a password for analysis."],
            "length": 0,
            "diversity": 0,
            "common": False,
            "keyboard": False,
            "sequence": False,
            "repetition": False,
            "personal": False,
        }

    length = len(password)

    # ---------------- LENGTH ----------------

    if length >= 16:
        score += 30
    elif length >= 12:
        score += 24
    elif length >= 8:
        score += 16
    else:
        score += 5
        findings.append("Password length is below the recommended minimum.")
        recommendations.append("Use at least 12–16 characters.")

    # ---------------- CHARACTER DIVERSITY ----------------

    diversity = 0

    if re.search(r"[a-z]", password):
        diversity += 1
        score += 7

    if re.search(r"[A-Z]", password):
        diversity += 1
        score += 7

    if re.search(r"\d", password):
        diversity += 1
        score += 7

    if re.search(r"[^A-Za-z0-9]", password):
        diversity += 1
        score += 7

    if diversity < 3:
        findings.append("Character diversity is limited.")
        recommendations.append(
            "Combine uppercase, lowercase, numbers and symbols."
        )

    # ---------------- COMMON PASSWORD ----------------

    common = password.lower() in COMMON_PASSWORDS

    if common:
        score -= 35
        findings.append("Credential matches a common password pattern.")
        recommendations.append("Never use common or easily guessed passwords.")

    # ---------------- KEYBOARD PATTERN ----------------

    keyboard = any(
        pattern in password.lower()
        for pattern in KEYBOARD_PATTERNS
    )

    if keyboard:
        score -= 15
        findings.append("Keyboard sequence detected.")
        recommendations.append("Avoid keyboard patterns such as QWERTY or ASDF.")

    # ---------------- SEQUENCE ----------------

    sequence = False

    for seq in SEQUENCES:
        if seq in password.lower():
            sequence = True
            break

    if sequence:
        score -= 10
        findings.append("Sequential character pattern detected.")
        recommendations.append("Avoid predictable numeric or alphabetic sequences.")

    # ---------------- REPETITION ----------------

    repetition = bool(
        re.search(r"(.)\1\1", password)
    )

    if repetition:
        score -= 10
        findings.append("Repeated character pattern detected.")
        recommendations.append("Avoid repeated characters such as aaa or 111.")

    # ---------------- PERSONAL PATTERN ----------------

    personal = any(
        pattern in password.lower()
        for pattern in PERSONAL_PATTERNS
    )

    if personal:
        score -= 10
        findings.append("Potentially predictable personal/common word detected.")
        recommendations.append(
            "Avoid names, account names, common words and contextual terms."
        )

    # ---------------- SPACES ----------------

    if " " in password:
        findings.append("Whitespace detected in credential.")
        recommendations.append(
            "Avoid accidental spaces at the beginning or end."
        )

    # ---------------- ENTROPY ----------------

    entropy = calculate_entropy(password)

    if entropy >= 70:
        score += 8
    elif entropy >= 50:
        score += 5
    else:
        findings.append("Estimated entropy is relatively low.")
        recommendations.append("Increase length and character diversity.")

    score = max(0, min(100, score))

    if score >= 85:
        label = "STRONG"
    elif score >= 70:
        label = "GOOD"
    elif score >= 50:
        label = "MODERATE"
    elif score >= 30:
        label = "WEAK"
    else:
        label = "CRITICAL"

    if not findings:
        findings.append("No major weakness detected by the local analysis engine.")

    if not recommendations:
        recommendations.append(
            "Credential meets the local security assessment criteria."
        )

    return {
        "score": score,
        "label": label,
        "entropy": round(entropy, 2),
        "findings": findings,
        "recommendations": recommendations,
        "length": length,
        "diversity": diversity,
        "common": common,
        "keyboard": keyboard,
        "sequence": sequence,
        "repetition": repetition,
        "personal": personal,
    }


# ============================================================
# EDUCATIONAL ATTACK-RISK SIMULATION
# ============================================================

def simulate_attack(password, analysis):
    """
    Educational heuristic only.
    This does NOT perform a real password attack.
    """

    risk = 100 - analysis["score"]

    if analysis["common"]:
        risk += 25

    if analysis["keyboard"]:
        risk += 15

    if analysis["sequence"]:
        risk += 10

    if analysis["repetition"]:
        risk += 10

    if analysis["personal"]:
        risk += 10

    if len(password) >= 16:
        risk -= 20
    elif len(password) >= 12:
        risk -= 10

    risk = max(0, min(100, int(risk)))

    if risk >= 75:
        level = "HIGH"
    elif risk >= 45:
        level = "MEDIUM"
    else:
        level = "LOW"

    return risk, level


# ============================================================
# MAIN APPLICATION
# ============================================================

class SecurePassX:

    def __init__(self, root):

        self.root = root
        self.root.title(
            f"{APP_NAME} — Cybersecurity Defense Console"
        )

        self.root.geometry("1280x780")
        self.root.minsize(1100, 700)
        self.root.configure(bg=BG)

        self.history = load_history()

        self.current_analysis = None
        self.current_account = "Other"
        self.current_risk = 0
        self.current_risk_level = "UNKNOWN"

        self.otp_running = False
        self.otp_secret = None
        self.otp_object = None

        self.last_generated_password = None

        self.build_style()
        self.build_shell()
        self.show_page("dashboard")

    # ========================================================
    # STYLE
    # ========================================================

    def build_style(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Treeview",
            background=PANEL,
            foreground=TEXT,
            fieldbackground=PANEL,
            rowheight=30,
            borderwidth=0,
            font=(FONT, 10),
        )

        style.configure(
            "Treeview.Heading",
            background=PANEL2,
            foreground=TEXT,
            font=(FONT, 10, "bold"),
            borderwidth=0,
        )

        style.map(
            "Treeview",
            background=[("selected", "#1e40af")],
            foreground=[("selected", "white")],
        )

        style.configure(
            "TCombobox",
            fieldbackground=CARD,
            background=CARD,
            foreground=TEXT,
            arrowcolor=TEXT,
        )

        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=PANEL2,
            background=BLUE,
            bordercolor=PANEL2,
            lightcolor=BLUE,
            darkcolor=BLUE,
        )

    # ========================================================
    # BASIC UI HELPERS
    # ========================================================

    def clear_frame(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()

    def create_button(
        self,
        parent,
        text,
        command,
        bg=BLUE,
        fg="#06111f",
        width=None,
    ):

        kwargs = {
            "text": text,
            "command": command,
            "bg": bg,
            "fg": fg,
            "font": (FONT, 10, "bold"),
            "relief": "flat",
            "bd": 0,
            "cursor": "hand2",
            "padx": 14,
            "pady": 9,
            "activebackground": bg,
            "activeforeground": fg,
        }

        if width:
            kwargs["width"] = width

        return tk.Button(parent, **kwargs)

    def card(self, parent, title=None):

        frame = tk.Frame(
            parent,
            bg=CARD,
            highlightbackground=BORDER,
            highlightthickness=1,
        )

        if title:
            tk.Label(
                frame,
                text=title,
                bg=CARD,
                fg=TEXT,
                font=(FONT, 11, "bold"),
            ).pack(
                anchor="w",
                padx=16,
                pady=(14, 8),
            )

        return frame

    def add_heading(self, parent, title, subtitle=None):

        tk.Label(
            parent,
            text=title,
            bg=BG,
            fg=TEXT,
            font=(FONT, 24, "bold"),
        ).pack(anchor="w")

        if subtitle:
            tk.Label(
                parent,
                text=subtitle,
                bg=BG,
                fg=MUTED,
                font=(FONT, 10),
            ).pack(
                anchor="w",
                pady=(3, 18),
            )

    # ========================================================
    # SHELL
    # ========================================================

    def build_shell(self):

        self.sidebar = tk.Frame(
            self.root,
            bg="#08101e",
            width=220,
        )

        self.sidebar.pack(
            side="left",
            fill="y",
        )

        self.sidebar.pack_propagate(False)

        # Logo

        tk.Label(
            self.sidebar,
            text="SECUREPASS",
            bg="#08101e",
            fg=TEXT,
            font=(FONT, 18, "bold"),
        ).pack(
            anchor="w",
            padx=22,
            pady=(25, 0),
        )

        tk.Label(
            self.sidebar,
            text="X  •  DEFENSE CONSOLE",
            bg="#08101e",
            fg=BLUE,
            font=(FONT, 8, "bold"),
        ).pack(
            anchor="w",
            padx=22,
            pady=(0, 25),
        )

        self.nav_buttons = {}

        navigation = [
            ("dashboard", "◈  Security Guardian"),
            ("generator", "⚿  Credential Generator"),
            ("twofa", "◉  2FA Security Lab"),
            ("audit", "▣  Security Audit Center"),
            ("history", "◫  Security History"),
            ("reports", "▤  Reports & Evidence"),
        ]

        for page_id, label in navigation:

            button = tk.Button(
                self.sidebar,
                text=label,
                command=lambda p=page_id: self.show_page(p),
                bg="#08101e",
                fg=MUTED,
                activebackground=PANEL2,
                activeforeground=TEXT,
                relief="flat",
                bd=0,
                anchor="w",
                padx=22,
                pady=12,
                font=(FONT, 10, "bold"),
                cursor="hand2",
            )

            button.pack(fill="x", padx=10, pady=2)

            self.nav_buttons[page_id] = button

        # Bottom status

        bottom = tk.Frame(
            self.sidebar,
            bg="#08101e",
        )

        bottom.pack(
            side="bottom",
            fill="x",
            padx=18,
            pady=20,
        )

        tk.Label(
            bottom,
            text="SYSTEM STATUS",
            bg="#08101e",
            fg=MUTED,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w")

        tk.Label(
            bottom,
            text="●  LOCAL DEFENSE ENGINE",
            bg="#08101e",
            fg=GREEN,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", pady=(4, 2))

        tk.Label(
            bottom,
            text=f"Version {APP_VERSION}",
            bg="#08101e",
            fg="#64748b",
            font=(FONT, 8),
        ).pack(anchor="w")

        # Main area

        self.main_area = tk.Frame(
            self.root,
            bg=BG,
        )

        self.main_area.pack(
            side="left",
            fill="both",
            expand=True,
        )

        # Top bar

        self.topbar = tk.Frame(
            self.main_area,
            bg=BG,
            height=55,
        )

        self.topbar.pack(
            fill="x",
            padx=28,
            pady=(15, 0),
        )

        self.topbar.pack_propagate(False)

        self.page_status = tk.Label(
            self.topbar,
            text="SYSTEM READY",
            bg=BG,
            fg=GREEN,
            font=(FONT, 9, "bold"),
        )

        self.page_status.pack(
            side="right",
            pady=12,
        )

        self.content = tk.Frame(
            self.main_area,
            bg=BG,
        )

        self.content.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=(8, 25),
        )

    # ========================================================
    # PAGE SWITCHING
    # ========================================================

    def show_page(self, page):

        for button in self.nav_buttons.values():
            button.configure(
                bg="#08101e",
                fg=MUTED,
            )

        if page in self.nav_buttons:
            self.nav_buttons[page].configure(
                bg=PANEL2,
                fg=TEXT,
            )

        self.clear_frame(self.content)

        if page == "dashboard":
            self.build_dashboard()

        elif page == "generator":
            self.build_generator()

        elif page == "twofa":
            self.build_twofa()

        elif page == "audit":
            self.build_audit()

        elif page == "history":
            self.build_history()

        elif page == "reports":
            self.build_reports()

        self.page_status.configure(
            text=f"● {page.upper()}",
            fg=GREEN,
        )

    # ========================================================
    # DASHBOARD
    # ========================================================

    def build_dashboard(self):

        self.add_heading(
            self.content,
            "Security Guardian",
            "Adaptive credential assessment and threat detection console",
        )

        # Top control panel

        control = self.card(
            self.content,
            "Credential Security Assessment",
        )

        control.pack(
            fill="x",
            pady=(0, 14),
        )

        row = tk.Frame(
            control,
            bg=CARD,
        )

        row.pack(
            fill="x",
            padx=16,
            pady=(0, 16),
        )

        # Account

        tk.Label(
            row,
            text="Protected Asset",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9, "bold"),
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=(0, 10),
        )

        self.account_var = tk.StringVar(
            value=self.current_account
        )

        account_box = ttk.Combobox(
            row,
            textvariable=self.account_var,
            values=list(ACCOUNT_RISK.keys()),
            state="readonly",
            width=18,
        )

        account_box.grid(
            row=1,
            column=0,
            padx=(0, 15),
            pady=(5, 0),
        )

        # Password

        tk.Label(
            row,
            text="Credential Under Assessment",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9, "bold"),
        ).grid(
            row=0,
            column=1,
            sticky="w",
        )

        self.password_var = tk.StringVar()

        self.password_entry = tk.Entry(
            row,
            textvariable=self.password_var,
            show="•",
            bg="#0f172a",
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=(FONT, 11),
            width=36,
        )

        self.password_entry.grid(
            row=1,
            column=1,
            pady=(5, 0),
        )

        self.show_password_var = tk.BooleanVar()

        tk.Checkbutton(
            row,
            text="Show",
            variable=self.show_password_var,
            command=self.toggle_password,
            bg=CARD,
            fg=MUTED,
            selectcolor=CARD,
            activebackground=CARD,
            activeforeground=TEXT,
            font=(FONT, 9),
        ).grid(
            row=1,
            column=2,
            padx=8,
        )

        self.twofa_var = tk.BooleanVar()

        tk.Checkbutton(
            row,
            text="2FA Enabled",
            variable=self.twofa_var,
            bg=CARD,
            fg=TEXT,
            selectcolor=CARD,
            activebackground=CARD,
            activeforeground=TEXT,
            font=(FONT, 9, "bold"),
        ).grid(
            row=1,
            column=3,
            padx=10,
        )

        self.create_button(
            row,
            "RUN SECURITY ASSESSMENT",
            self.run_assessment,
            bg=BLUE,
        ).grid(
            row=1,
            column=4,
            padx=(10, 0),
        )

        self.create_button(
            row,
            "CLEAR",
            self.clear_assessment,
            bg="#334155",
            fg=TEXT,
        ).grid(
            row=1,
            column=5,
            padx=(8, 0),
        )

        # Main grid

        grid = tk.Frame(
            self.content,
            bg=BG,
        )

        grid.pack(
            fill="both",
            expand=True,
        )

        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        grid.columnconfigure(2, weight=1)

        grid.rowconfigure(0, weight=1)
        grid.rowconfigure(1, weight=1)

        # Posture

        posture = self.card(
            grid,
            "Security Posture",
        )

        posture.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 8),
            pady=(0, 8),
        )

        self.posture_canvas = tk.Canvas(
            posture,
            width=220,
            height=150,
            bg=CARD,
            highlightthickness=0,
        )

        self.posture_canvas.pack(
            pady=(5, 0),
        )

        self.posture_score_label = tk.Label(
            posture,
            text="-- / 100",
            bg=CARD,
            fg=TEXT,
            font=(FONT, 20, "bold"),
        )

        self.posture_score_label.pack()

        self.posture_label = tk.Label(
            posture,
            text="Awaiting assessment",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9, "bold"),
        )

        self.posture_label.pack(
            pady=(2, 12),
        )

        # Telemetry

        telemetry = self.card(
            grid,
            "Security Telemetry",
        )

        telemetry.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=8,
            pady=(0, 8),
        )

        self.telemetry_labels = {}

        telemetry_items = [
            ("Entropy", "-- bits"),
            ("Length", "--"),
            ("Character Diversity", "-- / 4"),
            ("Attack Risk", "--"),
            ("Asset Sensitivity", "--"),
            ("Credential ID", "--"),
        ]

        for name, value in telemetry_items:

            r = tk.Frame(
                telemetry,
                bg=CARD,
            )

            r.pack(
                fill="x",
                padx=16,
                pady=6,
            )

            tk.Label(
                r,
                text=name,
                bg=CARD,
                fg=MUTED,
                font=(FONT, 9),
            ).pack(
                side="left",
            )

            label = tk.Label(
                r,
                text=value,
                bg=CARD,
                fg=TEXT,
                font=(FONT, 9, "bold"),
            )

            label.pack(
                side="right",
            )

            self.telemetry_labels[name] = label

        # Threat Detection

        threat = self.card(
            grid,
            "Threat Detection",
        )

        threat.grid(
            row=0,
            column=2,
            sticky="nsew",
            padx=(8, 0),
            pady=(0, 8),
        )

        self.threat_level_label = tk.Label(
            threat,
            text="NO ASSESSMENT",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 18, "bold"),
        )

        self.threat_level_label.pack(
            pady=(25, 5),
        )

        self.threat_risk_label = tk.Label(
            threat,
            text="Risk Index: --",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 10),
        )

        self.threat_risk_label.pack()

        self.threat_detail_label = tk.Label(
            threat,
            text="Run an assessment to detect credential weaknesses.",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9),
            wraplength=280,
            justify="center",
        )

        self.threat_detail_label.pack(
            padx=20,
            pady=15,
        )

        # Findings

        findings = self.card(
            grid,
            "Detected Security Findings",
        )

        findings.grid(
            row=1,
            column=0,
            columnspan=2,
            sticky="nsew",
            padx=(0, 8),
        )

        self.findings_text = tk.Text(
            findings,
            bg=CARD,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=(FONT, 9),
            wrap="word",
            height=8,
        )

        self.findings_text.pack(
            fill="both",
            expand=True,
            padx=16,
            pady=(0, 16),
        )

        self.findings_text.insert(
            "end",
            "No assessment performed yet.\n\n"
            "Enter a credential above and run the security assessment.",
        )

        self.findings_text.configure(
            state="disabled"
        )

        # Recommendations

        recommendations = self.card(
            grid,
            "Defense Recommendations",
        )

        recommendations.grid(
            row=1,
            column=2,
            sticky="nsew",
            padx=(8, 0),
        )

        self.recommendations_text = tk.Text(
            recommendations,
            bg=CARD,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=(FONT, 9),
            wrap="word",
            height=8,
        )

        self.recommendations_text.pack(
            fill="both",
            expand=True,
            padx=16,
            pady=(0, 16),
        )

        self.recommendations_text.insert(
            "end",
            "Security recommendations will appear here.",
        )

        self.recommendations_text.configure(
            state="disabled"
        )

    # ========================================================
    # DASHBOARD ACTIONS
    # ========================================================

    def toggle_password(self):

        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="•")

    def update_text_widget(self, widget, text):

        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    def draw_posture(self, score):

        self.posture_canvas.delete("all")

        width = 220
        height = 150

        self.posture_canvas.create_oval(
            40,
            10,
            180,
            150,
            outline="#334155",
            width=12,
        )

        if score >= 85:
            color = GREEN
        elif score >= 70:
            color = BLUE
        elif score >= 50:
            color = YELLOW
        else:
            color = RED

        extent = int((score / 100) * 360)

        self.posture_canvas.create_arc(
            40,
            10,
            180,
            150,
            start=90,
            extent=-extent,
            outline=color,
            width=12,
            style="arc",
        )

        self.posture_canvas.create_text(
            width // 2,
            80,
            text=str(score),
            fill=TEXT,
            font=(FONT, 25, "bold"),
        )

    def run_assessment(self):

        password = self.password_var.get()

        if not password:
            messagebox.showwarning(
                "Credential Required",
                "Enter a password before running the security assessment.",
            )
            return

        account = self.account_var.get()

        analysis = analyze_password(password)
        risk, risk_level = simulate_attack(
            password,
            analysis,
        )

        self.current_analysis = analysis
        self.current_account = account
        self.current_risk = risk
        self.current_risk_level = risk_level

        # 2FA adjustment

        score = analysis["score"]

        if self.twofa_var.get():
            score = min(100, score + 10)

        self.draw_posture(score)

        self.posture_score_label.configure(
            text=f"{score} / 100"
        )

        if score >= 85:
            posture_text = "STRONG SECURITY POSTURE"
            posture_color = GREEN

        elif score >= 70:
            posture_text = "GOOD SECURITY POSTURE"
            posture_color = BLUE

        elif score >= 50:
            posture_text = "MODERATE SECURITY POSTURE"
            posture_color = YELLOW

        else:
            posture_text = "HIGH-RISK SECURITY POSTURE"
            posture_color = RED

        self.posture_label.configure(
            text=posture_text,
            fg=posture_color,
        )

        # Telemetry

        self.telemetry_labels["Entropy"].configure(
            text=f"{analysis['entropy']} bits"
        )

        self.telemetry_labels["Length"].configure(
            text=f"{analysis['length']} chars"
        )

        self.telemetry_labels["Character Diversity"].configure(
            text=f"{analysis['diversity']} / 4"
        )

        self.telemetry_labels["Attack Risk"].configure(
            text=f"{risk}%"
        )

        self.telemetry_labels["Asset Sensitivity"].configure(
            text=f"{ACCOUNT_RISK.get(account, 60)}/100"
        )

        self.telemetry_labels["Credential ID"].configure(
            text=credential_fingerprint(password)
        )

        # Threat

        self.threat_level_label.configure(
            text=f"{risk_level} RISK"
        )

        if risk_level == "HIGH":
            self.threat_level_label.configure(
                fg=RED
            )

        elif risk_level == "MEDIUM":
            self.threat_level_label.configure(
                fg=YELLOW
            )

        else:
            self.threat_level_label.configure(
                fg=GREEN
            )

        self.threat_risk_label.configure(
            text=f"Educational Risk Index: {risk}%"
        )

        self.threat_detail_label.configure(
            text=(
                "This is a local educational heuristic. "
                "It does not perform a real password attack."
            )
        )

        # Findings

        finding_lines = []

        for item in analysis["findings"]:
            finding_lines.append("• " + item)

        if self.twofa_var.get():
            finding_lines.append(
                "\n✓ Multi-factor protection is enabled."
            )
        else:
            finding_lines.append(
                "\n⚠ Multi-factor protection is not enabled."
            )

        self.update_text_widget(
            self.findings_text,
            "\n".join(finding_lines),
        )

        # Recommendations

        recommendations = list(
            analysis["recommendations"]
        )

        if not self.twofa_var.get():
            recommendations.append(
                "Enable TOTP-based two-factor authentication."
            )

        if account in ["Banking", "PhonePe", "Gmail"]:
            recommendations.append(
                "High-sensitivity assets should use unique credentials and MFA."
            )

        self.update_text_widget(
            self.recommendations_text,
            "\n".join(
                "• " + r
                for r in recommendations
            ),
        )

        # Save audit record

        self.save_assessment(
            password,
            account,
            score,
            analysis,
            risk,
            risk_level,
        )

        self.page_status.configure(
            text="● ASSESSMENT COMPLETED",
            fg=GREEN,
        )

    def save_assessment(
        self,
        password,
        account,
        score,
        analysis,
        risk,
        risk_level,
    ):

        record = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "account": account,
            "score": score,
            "strength": analysis["label"],
            "entropy": analysis["entropy"],
            "length": analysis["length"],
            "diversity": analysis["diversity"],
            "attack_risk": risk,
            "risk_level": risk_level,
            "twofa": self.twofa_var.get(),
            "credential_fingerprint": credential_fingerprint(password),
            "findings": analysis["findings"],
            "recommendations": analysis["recommendations"],
        }

        self.history.insert(
            0,
            record,
        )

        self.history = self.history[:100]

        save_history(self.history)

    def clear_assessment(self):

        self.password_var.set("")

        self.current_analysis = None

        self.posture_score_label.configure(
            text="-- / 100"
        )

        self.posture_label.configure(
            text="Awaiting assessment",
            fg=MUTED,
        )

        self.draw_posture(0)

        for name, value in [
            ("Entropy", "-- bits"),
            ("Length", "--"),
            ("Character Diversity", "-- / 4"),
            ("Attack Risk", "--"),
            ("Asset Sensitivity", "--"),
            ("Credential ID", "--"),
        ]:
            self.telemetry_labels[name].configure(
                text=value
            )

        self.threat_level_label.configure(
            text="NO ASSESSMENT",
            fg=MUTED,
        )

        self.threat_risk_label.configure(
            text="Risk Index: --"
        )

        self.threat_detail_label.configure(
            text="Run an assessment to detect credential weaknesses."
        )

        self.update_text_widget(
            self.findings_text,
            "No assessment performed yet.",
        )

        self.update_text_widget(
            self.recommendations_text,
            "Security recommendations will appear here.",
        )

        self.page_status.configure(
            text="● READY",
            fg=GREEN,
        )

    # ========================================================
    # GENERATOR
    # ========================================================

    def build_generator(self):

        self.add_heading(
            self.content,
            "Credential Generator",
            "Cryptographically secure password generation using Python secrets",
        )

        wrapper = tk.Frame(
            self.content,
            bg=BG,
        )

        wrapper.pack(
            fill="both",
            expand=True,
        )

        wrapper.columnconfigure(0, weight=1)
        wrapper.columnconfigure(1, weight=1)

        settings = self.card(
            wrapper,
            "Generation Policy",
        )

        settings.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 8),
        )

        result = self.card(
            wrapper,
            "Generated Credential",
        )

        result.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(8, 0),
        )

        # Length

        tk.Label(
            settings,
            text="Password Length",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9, "bold"),
        ).pack(
            anchor="w",
            padx=18,
            pady=(18, 5),
        )

        self.generator_length = tk.IntVar(
            value=18
        )

        tk.Spinbox(
            settings,
            from_=8,
            to=64,
            textvariable=self.generator_length,
            bg="#0f172a",
            fg=TEXT,
            buttonbackground="#334155",
            insertbackground=TEXT,
            relief="flat",
            font=(FONT, 11),
            width=10,
        ).pack(
            anchor="w",
            padx=18,
        )

        self.gen_upper = tk.BooleanVar(value=True)
        self.gen_lower = tk.BooleanVar(value=True)
        self.gen_numbers = tk.BooleanVar(value=True)
        self.gen_symbols = tk.BooleanVar(value=True)

        checks = [
            ("Uppercase letters", self.gen_upper),
            ("Lowercase letters", self.gen_lower),
            ("Numbers", self.gen_numbers),
            ("Symbols", self.gen_symbols),
        ]

        for text, variable in checks:

            tk.Checkbutton(
                settings,
                text=text,
                variable=variable,
                bg=CARD,
                fg=TEXT,
                selectcolor=CARD,
                activebackground=CARD,
                activeforeground=TEXT,
                font=(FONT, 10),
            ).pack(
                anchor="w",
                padx=18,
                pady=3,
            )

        self.create_button(
            settings,
            "GENERATE SECURE CREDENTIAL",
            self.generate_password,
            bg=GREEN,
        ).pack(
            anchor="w",
            padx=18,
            pady=18,
        )

        tk.Label(
            settings,
            text=(
                "Generation uses Python's cryptographically secure "
                "secrets module rather than a predictable random generator."
            ),
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9),
            wraplength=430,
            justify="left",
        ).pack(
            anchor="w",
            padx=18,
            pady=5,
        )

        # Result

        self.generated_text = tk.Text(
            result,
            bg="#0b1220",
            fg=GREEN,
            insertbackground=GREEN,
            relief="flat",
            font=("Consolas", 13),
            height=5,
            wrap="word",
        )

        self.generated_text.pack(
            fill="x",
            padx=18,
            pady=(20, 10),
        )

        self.generated_text.insert(
            "end",
            "No credential generated yet."
        )

        self.generated_text.configure(
            state="disabled"
        )

        button_row = tk.Frame(
            result,
            bg=CARD,
        )

        button_row.pack(
            padx=18,
            pady=5,
            anchor="w",
        )

        self.create_button(
            button_row,
            "COPY",
            self.copy_generated_password,
            bg=BLUE,
        ).pack(
            side="left",
            padx=(0, 8),
        )

        self.create_button(
            button_row,
            "CLEAR",
            self.clear_generated_password,
            bg="#334155",
            fg=TEXT,
        ).pack(
            side="left",
        )

        tk.Label(
            result,
            text=(
                "Clipboard protection: the generated credential is "
                "automatically removed after 30 seconds if unchanged."
            ),
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9),
            wraplength=450,
            justify="left",
        ).pack(
            anchor="w",
            padx=18,
            pady=18,
        )

    def generate_password(self):

        try:
            length = int(
                self.generator_length.get()
            )
        except Exception:
            length = 18

        length = max(8, min(64, length))

        pools = []

        if self.gen_upper.get():
            pools.append(string.ascii_uppercase)

        if self.gen_lower.get():
            pools.append(string.ascii_lowercase)

        if self.gen_numbers.get():
            pools.append(string.digits)

        if self.gen_symbols.get():
            pools.append("!@#$%^&*()-_=+[]{};:,.?/")

        if not pools:
            messagebox.showwarning(
                "Generation Policy",
                "Select at least one character type.",
            )
            return

        # Guarantee one character from every selected category

        password_chars = [
            secrets.choice(pool)
            for pool in pools
        ]

        combined = "".join(pools)

        while len(password_chars) < length:
            password_chars.append(
                secrets.choice(combined)
            )

        secrets.SystemRandom().shuffle(
            password_chars
        )

        password = "".join(
            password_chars
        )

        self.last_generated_password = password

        self.generated_text.configure(
            state="normal"
        )

        self.generated_text.delete(
            "1.0",
            "end",
        )

        self.generated_text.insert(
            "end",
            password,
        )

        self.generated_text.configure(
            state="disabled"
        )

        self.page_status.configure(
            text="● SECURE CREDENTIAL GENERATED",
            fg=GREEN,
        )

    def copy_generated_password(self):

        if not self.last_generated_password:
            messagebox.showinfo(
                "Nothing to Copy",
                "Generate a credential first.",
            )
            return

        password = self.last_generated_password

        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.root.update()

        self.page_status.configure(
            text="● COPIED — CLIPBOARD PROTECTED",
            fg=GREEN,
        )

        self.root.after(
            30000,
            lambda p=password: self.clear_clipboard_if_same(p),
        )

    def clear_clipboard_if_same(self, password):

        try:
            current = self.root.clipboard_get()

            if current == password:
                self.root.clipboard_clear()
                self.page_status.configure(
                    text="● CLIPBOARD CLEARED",
                    fg=BLUE,
                )

        except Exception:
            pass

    def clear_generated_password(self):

        self.last_generated_password = None

        self.generated_text.configure(
            state="normal"
        )

        self.generated_text.delete(
            "1.0",
            "end",
        )

        self.generated_text.insert(
            "end",
            "No credential generated yet."
        )

        self.generated_text.configure(
            state="disabled"
        )

    # ========================================================
    # 2FA
    # ========================================================

    def build_twofa(self):

        self.add_heading(
            self.content,
            "2FA Security Lab",
            "Local TOTP-based multi-factor authentication demonstration",
        )

        wrapper = tk.Frame(
            self.content,
            bg=BG,
        )

        wrapper.pack(
            fill="both",
            expand=True,
        )

        wrapper.columnconfigure(0, weight=1)
        wrapper.columnconfigure(1, weight=1)

        setup = self.card(
            wrapper,
            "TOTP Enrollment",
        )

        setup.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 8),
        )

        display = self.card(
            wrapper,
            "Authenticator Display",
        )

        display.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(8, 0),
        )

        if not SECURITY_LIBRARIES:

            tk.Label(
                setup,
                text="2FA libraries unavailable",
                bg=CARD,
                fg=RED,
                font=(FONT, 16, "bold"),
            ).pack(
                pady=30
            )

            tk.Label(
                setup,
                text=(
                    'Install with:\n\n'
                    'pip install pyotp "qrcode[pil]" pillow'
                ),
                bg=CARD,
                fg=MUTED,
                font=("Consolas", 10),
                justify="left",
            ).pack(
                padx=20
            )

            return

        tk.Label(
            setup,
            text="TOTP Secret",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9, "bold"),
        ).pack(
            anchor="w",
            padx=18,
            pady=(18, 5),
        )

        self.secret_label = tk.Label(
            setup,
            text="No secret generated",
            bg="#0b1220",
            fg=GREEN,
            font=("Consolas", 11),
            wraplength=430,
        )

        self.secret_label.pack(
            fill="x",
            padx=18,
            pady=(0, 15),
        )

        self.create_button(
            setup,
            "GENERATE TOTP CONFIGURATION",
            self.generate_totp,
            bg=PURPLE,
            fg="#0b1120",
        ).pack(
            anchor="w",
            padx=18,
        )

        tk.Label(
            setup,
            text=(
                "This module demonstrates the TOTP concept locally. "
                "The QR contains a provisioning URI for an authenticator app."
            ),
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9),
            wraplength=430,
            justify="left",
        ).pack(
            anchor="w",
            padx=18,
            pady=20,
        )

        # QR

        self.qr_label = tk.Label(
            display,
            text="QR CODE\n\nGenerate TOTP configuration",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 11, "bold"),
            width=35,
            height=10,
        )

        self.qr_label.pack(
            pady=20,
        )

        self.otp_label = tk.Label(
            display,
            text="------",
            bg=CARD,
            fg=BLUE,
            font=("Consolas", 32, "bold"),
        )

        self.otp_label.pack()

        self.countdown_label = tk.Label(
            display,
            text="Waiting for TOTP configuration",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9),
        )

        self.countdown_label.pack(
            pady=(5, 20)
        )

    def generate_totp(self):

        if not SECURITY_LIBRARIES:
            return

        try:

            self.otp_secret = pyotp.random_base32()

            self.otp_object = pyotp.TOTP(
                self.otp_secret
            )

            uri = self.otp_object.provisioning_uri(
                name="SecurePass User",
                issuer_name="SECUREPASS X",
            )

            qr = qrcode.make(uri)

            qr.save(QR_FILE)

            image = Image.open(QR_FILE)
            image = image.resize(
                (230, 230)
            )

            self.qr_photo = ImageTk.PhotoImage(
                image
            )

            self.qr_label.configure(
                image=self.qr_photo,
                text="",
            )

            self.secret_label.configure(
                text=self.otp_secret
            )

            self.otp_running = True

            self.update_otp()

            self.page_status.configure(
                text="● TOTP CONFIGURATION CREATED",
                fg=GREEN,
            )

        except Exception as error:

            messagebox.showerror(
                "2FA Error",
                str(error),
            )

    def update_otp(self):

        if not self.otp_running:
            return

        try:

            if self.otp_object:

                otp = self.otp_object.now()

                remaining = (
                    30
                    - int(datetime.now().timestamp()) % 30
                )

                self.otp_label.configure(
                    text=otp
                )

                self.countdown_label.configure(
                    text=f"Code refreshes in {remaining} seconds"
                )

                self.root.after(
                    1000,
                    self.update_otp,
                )

        except Exception:
            pass

    # ========================================================
    # AUDIT CENTER
    # ========================================================

    def build_audit(self):

        self.add_heading(
            self.content,
            "Security Audit Center",
            "Review assessment evidence, security controls and event history",
        )

        # If no audit exists

        if not self.history:

            empty = self.card(
                self.content,
                "Audit Status",
            )

            empty.pack(
                fill="both",
                expand=True,
            )

            tk.Label(
                empty,
                text="NO AUDIT RECORDS",
                bg=CARD,
                fg=MUTED,
                font=(FONT, 22, "bold"),
            ).pack(
                pady=(100, 10)
            )

            tk.Label(
                empty,
                text=(
                    "Run a Security Assessment from the Security Guardian page "
                    "to create your first audit record."
                ),
                bg=CARD,
                fg=MUTED,
                font=(FONT, 10),
            ).pack()

            return

        latest = self.history[0]

        # Summary cards

        summary = tk.Frame(
            self.content,
            bg=BG,
        )

        summary.pack(
            fill="x",
            pady=(0, 12),
        )

        cards = [
            (
                "LATEST POSTURE",
                f"{latest.get('score', 0)}/100",
            ),
            (
                "THREAT LEVEL",
                latest.get("risk_level", "UNKNOWN"),
            ),
            (
                "2FA STATUS",
                "ENABLED"
                if latest.get("twofa")
                else "DISABLED",
            ),
            (
                "AUDIT EVENTS",
                str(len(self.history)),
            ),
        ]

        for title, value in cards:

            c = self.card(summary)

            c.pack(
                side="left",
                fill="x",
                expand=True,
                padx=4,
            )

            tk.Label(
                c,
                text=title,
                bg=CARD,
                fg=MUTED,
                font=(FONT, 8, "bold"),
            ).pack(
                pady=(12, 2)
            )

            tk.Label(
                c,
                text=value,
                bg=CARD,
                fg=TEXT,
                font=(FONT, 16, "bold"),
            ).pack(
                pady=(0, 12)
            )

        # Audit evidence

        evidence = self.card(
            self.content,
            "Latest Security Audit Evidence",
        )

        evidence.pack(
            fill="both",
            expand=True,
        )

        text = tk.Text(
            evidence,
            bg=CARD,
            fg=TEXT,
            relief="flat",
            font=("Consolas", 10),
            wrap="word",
        )

        text.pack(
            fill="both",
            expand=True,
            padx=16,
            pady=(0, 16),
        )

        audit_text = self.format_audit(latest)

        text.insert(
            "end",
            audit_text,
        )

        text.configure(
            state="disabled"
        )

    def format_audit(self, record):

        lines = []

        lines.append(
            "SECUREPASS X — SECURITY AUDIT RECORD"
        )
        lines.append(
            "=" * 65
        )
        lines.append(
            f"Audit Timestamp     : {record.get('timestamp', '-')}"
        )
        lines.append(
            f"Protected Asset     : {record.get('account', '-')}"
        )
        lines.append(
            f"Security Posture    : {record.get('score', 0)}/100"
        )
        lines.append(
            f"Credential Strength : {record.get('strength', '-')}"
        )
        lines.append(
            f"Entropy             : {record.get('entropy', 0)} bits"
        )
        lines.append(
            f"Credential Length   : {record.get('length', 0)} characters"
        )
        lines.append(
            f"Character Diversity : {record.get('diversity', 0)}/4"
        )
        lines.append(
            f"Attack Risk Index   : {record.get('attack_risk', 0)}%"
        )
        lines.append(
            f"Threat Level        : {record.get('risk_level', '-')}"
        )
        lines.append(
            f"2FA Protection      : "
            f"{'ENABLED' if record.get('twofa') else 'DISABLED'}"
        )
        lines.append(
            f"Credential ID       : "
            f"{record.get('credential_fingerprint', '-')}"
        )

        lines.append("")
        lines.append("SECURITY FINDINGS")
        lines.append("-" * 65)

        for finding in record.get(
            "findings",
            [],
        ):
            lines.append(
                "[!] " + finding
            )

        lines.append("")
        lines.append("DEFENSE RECOMMENDATIONS")
        lines.append("-" * 65)

        for recommendation in record.get(
            "recommendations",
            [],
        ):
            lines.append(
                "[+] " + recommendation
            )

        lines.append("")
        lines.append("AUDIT EVENT TIMELINE")
        lines.append("-" * 65)

        timeline = [
            "Credential submitted for local assessment",
            "Password strength engine executed",
            "Entropy calculation completed",
            "Pattern detection completed",
            "Threat-risk heuristic evaluated",
            "Security posture calculated",
            "Defense recommendations generated",
            "Audit record stored without plaintext password",
        ]

        if record.get("twofa"):
            timeline.append(
                "Multi-factor protection marked as enabled"
            )

        for index, event in enumerate(
            timeline,
            1,
        ):
            lines.append(
                f"{index:02d}. {event}"
            )

        lines.append("")
        lines.append(
            "NOTE: This application performs local educational security analysis."
        )
        lines.append(
            "It does not conduct real attacks or access external breach databases."
        )

        return "\n".join(lines)

    # ========================================================
    # HISTORY
    # ========================================================

    def build_history(self):

        self.add_heading(
            self.content,
            "Security History",
            "Stored assessment metadata — plaintext passwords are never recorded",
        )

        toolbar = tk.Frame(
            self.content,
            bg=BG,
        )

        toolbar.pack(
            fill="x",
            pady=(0, 10),
        )

        self.create_button(
            toolbar,
            "REFRESH",
            self.refresh_history,
            bg="#334155",
            fg=TEXT,
        ).pack(
            side="left"
        )

        self.create_button(
            toolbar,
            "CLEAR HISTORY",
            self.clear_history,
            bg=RED,
        ).pack(
            side="left",
            padx=8,
        )

        table_card = self.card(
            self.content
        )

        table_card.pack(
            fill="both",
            expand=True,
        )

        columns = (
            "time",
            "account",
            "score",
            "strength",
            "risk",
            "2fa",
            "fingerprint",
        )

        self.history_tree = ttk.Treeview(
            table_card,
            columns=columns,
            show="headings",
        )

        headings = {
            "time": "Timestamp",
            "account": "Asset",
            "score": "Score",
            "strength": "Strength",
            "risk": "Risk",
            "2fa": "2FA",
            "fingerprint": "Credential ID",
        }

        widths = {
            "time": 150,
            "account": 120,
            "score": 70,
            "strength": 100,
            "risk": 70,
            "2fa": 70,
            "fingerprint": 140,
        }

        for column in columns:

            self.history_tree.heading(
                column,
                text=headings[column],
            )

            self.history_tree.column(
                column,
                width=widths[column],
                anchor="center",
            )

        scrollbar = ttk.Scrollbar(
            table_card,
            orient="vertical",
            command=self.history_tree.yview,
        )

        self.history_tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.history_tree.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(12, 0),
            pady=12,
        )

        scrollbar.pack(
            side="right",
            fill="y",
            padx=(0, 12),
            pady=12,
        )

        self.refresh_history()

    def refresh_history(self):

        if not hasattr(
            self,
            "history_tree"
        ):
            return

        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        self.history = load_history()

        for record in self.history:

            self.history_tree.insert(
                "",
                "end",
                values=(
                    record.get("timestamp", "-"),
                    record.get("account", "-"),
                    record.get("score", "-"),
                    record.get("strength", "-"),
                    f"{record.get('attack_risk', '-')}%",
                    "YES"
                    if record.get("twofa")
                    else "NO",
                    record.get(
                        "credential_fingerprint",
                        "-",
                    ),
                ),
            )

    def clear_history(self):

        answer = messagebox.askyesno(
            "Clear Security History",
            (
                "Delete all stored security assessment metadata?\n\n"
                "This cannot be undone."
            ),
        )

        if not answer:
            return

        self.history = []

        save_history(
            self.history
        )

        self.refresh_history()

        self.page_status.configure(
            text="● HISTORY CLEARED",
            fg=YELLOW,
        )

    # ========================================================
    # REPORTS
    # ========================================================

    def build_reports(self):

        self.add_heading(
            self.content,
            "Reports & Evidence",
            "Export security evidence for project demonstration and documentation",
        )

        wrapper = tk.Frame(
            self.content,
            bg=BG,
        )

        wrapper.pack(
            fill="both",
            expand=True,
        )

        wrapper.columnconfigure(0, weight=1)
        wrapper.columnconfigure(1, weight=1)

        report = self.card(
            wrapper,
            "Audit Evidence Export",
        )

        report.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 8),
        )

        tk.Label(
            report,
            text=(
                "Generate a professional text-based security audit "
                "containing the latest assessment, findings, controls "
                "and event timeline."
            ),
            bg=CARD,
            fg=MUTED,
            font=(FONT, 10),
            wraplength=450,
            justify="left",
        ).pack(
            anchor="w",
            padx=18,
            pady=18,
        )

        self.create_button(
            report,
            "EXPORT SECURITY AUDIT",
            self.export_audit,
            bg=BLUE,
        ).pack(
            anchor="w",
            padx=18,
            pady=5,
        )

        history = self.card(
            wrapper,
            "Security Dataset Export",
        )

        history.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(8, 0),
        )

        tk.Label(
            history,
            text=(
                "Export assessment metadata as JSON. "
                "The exported history does not contain plaintext passwords."
            ),
            bg=CARD,
            fg=MUTED,
            font=(FONT, 10),
            wraplength=450,
            justify="left",
        ).pack(
            anchor="w",
            padx=18,
            pady=18,
        )

        self.create_button(
            history,
            "EXPORT HISTORY JSON",
            self.export_history_json,
            bg=GREEN,
        ).pack(
            anchor="w",
            padx=18,
            pady=5,
        )

        # Pipeline

        pipeline = self.card(
            self.content,
            "Defense Processing Pipeline",
        )

        pipeline.pack(
            fill="x",
            pady=(14, 0),
        )

        pipeline_text = (
            "01  CREDENTIAL INPUT\n"
            "       ↓\n"
            "02  STRENGTH ANALYSIS\n"
            "       ↓\n"
            "03  ENTROPY & PATTERN DETECTION\n"
            "       ↓\n"
            "04  THREAT-RISK ASSESSMENT\n"
            "       ↓\n"
            "05  SECURITY POSTURE CALCULATION\n"
            "       ↓\n"
            "06  DEFENSE RECOMMENDATIONS\n"
            "       ↓\n"
            "07  AUDIT RECORD & EVIDENCE"
        )

        tk.Label(
            pipeline,
            text=pipeline_text,
            bg=CARD,
            fg=CYAN,
            font=("Consolas", 10, "bold"),
            justify="left",
        ).pack(
            anchor="w",
            padx=20,
            pady=15,
        )

    def export_audit(self):

        if not self.history:

            messagebox.showinfo(
                "No Audit Available",
                "Run a security assessment first.",
            )

            return

        latest = self.history[0]

        filename = filedialog.asksaveasfilename(
            title="Export Security Audit",
            defaultextension=".txt",
            filetypes=[
                ("Text File", "*.txt"),
                ("All Files", "*.*"),
            ],
            initialfile="SecurePass_X_Security_Audit.txt",
        )

        if not filename:
            return

        try:

            with open(
                filename,
                "w",
                encoding="utf-8",
            ) as file:

                file.write(
                    self.format_audit(latest)
                )

            messagebox.showinfo(
                "Audit Exported",
                f"Security audit saved successfully.\n\n{filename}",
            )

            self.page_status.configure(
                text="● AUDIT EXPORTED",
                fg=GREEN,
            )

        except Exception as error:

            messagebox.showerror(
                "Export Error",
                str(error),
            )

    def export_history_json(self):

        if not self.history:

            messagebox.showinfo(
                "No History",
                "There is no security history to export.",
            )

            return

        filename = filedialog.asksaveasfilename(
            title="Export Security History",
            defaultextension=".json",
            filetypes=[
                ("JSON File", "*.json"),
                ("All Files", "*.*"),
            ],
            initialfile="SecurePass_X_History.json",
        )

        if not filename:
            return

        try:

            with open(
                filename,
                "w",
                encoding="utf-8",
            ) as file:

                json.dump(
                    self.history,
                    file,
                    indent=4,
                )

            messagebox.showinfo(
                "History Exported",
                f"Security history exported successfully.\n\n{filename}",
            )

            self.page_status.configure(
                text="● HISTORY EXPORTED",
                fg=GREEN,
            )

        except Exception as error:

            messagebox.showerror(
                "Export Error",
                str(error),
            )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = SecurePassX(
        root
    )

    root.mainloop()