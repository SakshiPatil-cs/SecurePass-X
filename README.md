# 🔐 SECUREPASS X - Cybersecurity Credential Defense & Audit Console

A Python-Based Cybersecurity Application.

SECUREPASS X helps users check password security, generate strong credentials, and audit account security using Two-Factor Authentication (2FA) - all through a simple Graphical User Interface.

## ✨ Features

- 🔍 Security Guardian - Password Strength Checker with Score, Entropy, Crack Time, Attack Risk & Threat Level
- 🎲 Credential Generator - Generates strong, unpredictable passwords using secure random generation
- 🔐 2FA Security Lab - TOTP-based 2FA with Secret, QR Code & Time-based OTP
- 🛡️ Security Audit Center - Overall Security Score, 2FA Status, Audit Events & Security Findings
- 🕒 Security History - Maintains local history of all past assessments
- 📄 Reports & Evidence - Export Session Report, History (CSV / JSON), Audit Log & Forensic Package

## 🛠️ Tech Used
- Python
- Tkinter (GUI)
- Python `secrets` / Secure Random Generation
- TOTP (Time-Based One-Time Password)
- QR Code Generation

## 🚀 How to Run

1. Download / Clone this repository.
2. Make sure Python is installed.
3. Install the required packages:

```
pip install pyotp "qrcode[pil]" Pillow
```

4. Run the application:

```
python main.py
```

## 📁 Project Structure

```
SECUREPASS-X/
│
├── main.py
├── securepass_x_history.json
└── README.md
```

## ⚠️ Note

SECUREPASS X is an educational cybersecurity project. Password strength and crack-time estimates are approximate and should not be treated as guarantees of security.
