# 🛡️ SOC Log Analysis, Alert Management & Incident Response Platform

A professional, web-based Security Operations Center (SOC) platform built with Python and Streamlit — demonstrating real-world security operations workflows including log collection, threat detection, alert triage, incident response, and compliance reporting.

> **Portfolio Project** — Designed to demonstrate skills relevant to SOC Analyst, Security Analyst, Blue Team, and GRC roles.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Log Collection & Parsing** | Upload `.txt` or `.csv` security logs with automatic parsing and normalization |
| **Rule-Based Detection Engine** | 4 threat detection rules with configurable thresholds |
| **MITRE ATT&CK Mapping** | Every detection maps to ATT&CK techniques (T1110, T1078, T1068, T1136) |
| **Alert Management** | Full alert lifecycle: OPEN → UNDER_INVESTIGATION → FALSE_POSITIVE / CLOSED |
| **Analyst Investigation** | Add investigation notes, attach verdicts (True/False Positive) |
| **Incident Management** | Create incidents from alerts, track through OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED |
| **RBAC (3 Roles)** | ADMIN, SOC_MANAGER, SOC_ANALYST — with granular permission enforcement |
| **PDF Reports** | Professional incident reports with MITRE mapping via ReportLab |
| **Audit Trail** | Immutable audit log of every platform action |
| **Security Dashboard** | Real-time KPIs, severity distribution, incident status, MITRE coverage charts |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Streamlit Frontend                     │
│  ┌─────────┬──────────┬──────────┬────────┬───────────┐ │
│  │Dashboard│ Alerts   │Incidents │Reports │User Mgmt  │ │
│  └────┬────┴────┬─────┴────┬─────┴───┬────┴─────┬─────┘ │
│       │         │          │         │          │        │
│  ┌────▼─────────▼──────────▼─────────▼──────────▼─────┐ │
│  │              RBAC Enforcement Layer                  │ │
│  └─────────────────────┬───────────────────────────────┘ │
│                        │                                  │
│  ┌─────────────────────▼───────────────────────────────┐ │
│  │          Backend Modules (Python)                    │ │
│  │  auth │ parser │ detector │ alerts │ incidents │ ... │ │
│  └─────────────────────┬───────────────────────────────┘ │
│                        │                                  │
│  ┌─────────────────────▼───────────────────────────────┐ │
│  │              SQLite Database (soc.db)                │ │
│  │  users │ uploaded_logs │ alerts │ incidents │ audit  │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## 🔍 Detection Rules

| # | Rule | Condition | Severity | MITRE Technique |
|---|---|---|---|---|
| 1 | **Brute Force Attack** | ≥5 failed logins from same IP within 5 minutes | HIGH | T1110 — Brute Force |
| 2 | **Suspicious Login Time** | Successful login between 12 AM – 5 AM | MEDIUM | T1078 — Valid Accounts |
| 3 | **Privilege Escalation** | PRIVILEGE_ESCALATION event detected | CRITICAL | T1068 — Exploitation for Priv Esc |
| 4 | **Excessive User Creation** | >3 users created within 10 minutes | HIGH | T1136 — Create Account |

---

## 👥 RBAC Roles & Permissions

| Permission | ADMIN | SOC_MANAGER | SOC_ANALYST |
|---|:---:|:---:|:---:|
| Create / Delete Users | ✅ | ❌ | ❌ |
| Manage Roles | ✅ | ❌ | ❌ |
| View Audit Logs | ✅ | ❌ | ❌ |
| View / Close Incidents | ✅ | ✅ | ❌ |
| Review Investigations | ✅ | ✅ | ❌ |
| View Reports | ✅ | ✅ | ❌ |
| View Alerts | ✅ | ✅ | ✅ |
| Upload Logs | ✅ | ✅ | ✅ |
| Investigate Alerts | ✅ | ❌ | ✅ |
| Add Notes / Create Incidents | ✅ | ❌ | ✅ |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/soc-platform.git
cd soc-platform

# Install dependencies
pip install -r requirements.txt

# Initialize the database
python database/init_db.py

# Launch the platform
streamlit run app.py
```

### Default Credentials

| Username | Password | Role |
|---|---|---|
| `admin` | `Admin@123` | ADMIN |

> ⚠️ Change the default password after first login.

---

## 📂 Project Structure

```
soc-platform/
├── app.py                      # Main Streamlit application
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── database/
│   ├── __init__.py
│   ├── init_db.py              # Schema creation & seeding
│   └── soc.db                  # SQLite database (generated)
├── modules/
│   ├── __init__.py
│   ├── auth.py                 # Authentication (bcrypt, sessions)
│   ├── rbac.py                 # Role-Based Access Control
│   ├── audit.py                # Audit trail logging
│   ├── parser.py               # Log parser (txt/csv)
│   ├── detector.py             # Rule-based detection engine
│   ├── alerts.py               # Alert lifecycle management
│   ├── incidents.py            # Incident lifecycle management
│   └── reports.py              # PDF report generation
├── logs/                       # Uploaded log files
├── sample_logs/
│   ├── auth_logs.txt           # Sample authentication logs
│   └── auth_logs.csv           # Sample logs (CSV format)
├── reports/                    # Generated PDF reports
└── assets/                     # Platform assets
```

---

## 🗄️ Database Schema

| Table | Purpose |
|---|---|
| `users` | User accounts with bcrypt-hashed passwords and roles |
| `uploaded_logs` | Parsed & normalized security log events |
| `alerts` | Generated security alerts with MITRE ATT&CK mapping |
| `incidents` | Incident records linked to confirmed alerts |
| `investigation_notes` | Analyst notes and verdicts attached to alerts |
| `audit_logs` | Immutable audit trail of all platform actions |

---

## 🔒 Security Considerations

- **Password Hashing** — bcrypt with default work factor (12 rounds)
- **No Plaintext Passwords** — Passwords are never stored or transmitted in plaintext
- **Input Validation** — All database queries use parameterized statements
- **File Upload Validation** — Extension whitelist (.txt, .csv) and 10MB size limit
- **RBAC Enforcement** — Every page and action checks permissions before execution
- **Audit Logging** — All significant actions are logged with username and timestamp
- **Generic Error Messages** — Login failures show generic messages to prevent enumeration
- **Session Management** — Streamlit server-side session state
- **Soft Delete** — Users are deactivated, not deleted, preserving audit integrity

---

## 🔮 Future Enhancements

- [ ] Additional log sources (Firewall, IDS/IPS, DNS, Proxy)
- [ ] Threat intelligence feed integration
- [ ] Email notifications for critical alerts
- [ ] Machine learning anomaly detection
- [ ] SIEM integration (Splunk, ELK)
- [ ] Active Directory / LDAP authentication
- [ ] SLA tracking for incident response times
- [ ] IOC (Indicators of Compromise) management
- [ ] Network traffic analysis module
- [ ] SOAR playbook automation

---

## 📝 License

This project is open source and available under the [MIT License](LICENSE).

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to open an issue or submit a pull request.

---

<p align="center">
  Built with 🛡️ for cybersecurity professionals
</p>
