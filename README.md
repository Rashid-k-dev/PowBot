<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-2.2+-green?style=for-the-badge&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

<h1 align="center">⚡ PowBot</h1>

<p align="center">
  <strong>A modern, web-based PowerShell remote administration framework with real-time client management and command execution capabilities.</strong>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-screenshots">Screenshots</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#%EF%B8%8F-configuration">Configuration</a> •
  <a href="#-disclaimer">Disclaimer</a>
</p>

---

## 🎯 Features

### 🖥️ Dashboard
- **Real-time Client Monitoring** – View connected clients with live status updates
- **Interactive Command Terminal** – Execute PowerShell commands on remote clients
- **Client Geolocation** – Automatic IP-based country detection with flag display
- **Multi-Select Operations** – Send commands to multiple clients simultaneously
- **Professional Dark Theme** – Modern, sleek UI with glassmorphism effects

### ⚙️ Script Builder
- **One-Liner Generator** – Generate ready-to-use PowerShell execution commands
- **Configurable Execution Policy** – Support for Bypass, Unrestricted, RemoteSigned, and AllSigned
- **Adjustable Check-in Interval** – Customize polling frequency
- **Optional Persistence** – Registry-based startup persistence mechanism
- **Script Obfuscation** – Built-in PowerShell obfuscation with sandbox evasion

### 🔒 Security
- **SSL/TLS Encryption** – Secure HTTPS communication in production
- **User Authentication** – Flask-Login with secure password hashing
- **OAuth Integration** – GitHub OAuth support for easy authentication
- **Session Management** – Secure session handling with Flask-WTF CSRF protection

### 🚀 Performance
- **Gevent WSGI Server** – High-performance async server for production
- **Long Polling** – Efficient command delivery with 30-second timeouts
- **Automatic Cleanup** – Inactive client removal after configurable timeout
- **SQLite Database** – Lightweight task and user storage

---

## 📸 Screenshots

### Dashboard - Client Management
<p align="center">
  <img src="screenshots/dashboard.png" alt="PowBot Dashboard" width="800">
</p>

*The main dashboard displays connected clients in a sortable DataTable with real-time status indicators. The integrated command terminal allows direct interaction with selected clients.*

### Settings - Script Builder
<p align="center">
  <img src="screenshots/settings.png" alt="PowBot Settings" width="800">
</p>

*The script configuration panel enables quick payload generation with customizable execution policies, check-in intervals, and persistence options.*

---

## 🛠 Installation

### Prerequisites
- Python 3.10+
- PowerShell 5.1+ (Windows) or PowerShell Core 7+ (Cross-platform)
- OpenSSL (for generating SSL certificates in production)

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/PowBot.git
   cd PowBot
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # Windows
   .\venv\Scripts\activate
   
   # Linux/macOS
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run in development mode**
   ```bash
   python runLocal.py
   ```

5. **Access the dashboard**
   - Open your browser and navigate to `http://127.0.0.1:5000`
   - Default credentials: Configure via the registration page

### Production Deployment

1. **Generate SSL certificates**
   ```bash
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout private.key -out certificate.crt
   ```

2. **Run in production mode**
   ```bash
   python runWeb.py
   ```
   
   The server will start on:
   - **HTTPS (Web Panel)**: Port 443
   - **HTTPS (API/C2)**: Port 4000

---

## 📖 Usage

### Generating a Payload

1. Navigate to **Settings** in the sidebar
2. Configure the following options:
   - **Target Endpoint**: Your server's URL (e.g., `https://yourserver.com`)
   - **Execution Policy**: Choose based on target environment
   - **Check-in Interval**: Time between client callbacks (in seconds)
   - **Enable Persistence**: Toggle registry persistence
3. Click **Generate One-Liner**
4. Copy the generated command

### Executing Commands

1. Navigate to the **Dashboard**
2. Select one or more clients using the checkboxes
3. Type your PowerShell command in the terminal
4. Press **Enter** or click the send button
5. View responses in the terminal output

### Example Commands

```powershell
# System information
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion

# List running processes
Get-Process | Select-Object -First 10 Name, CPU, WorkingSet

# Network connections
Get-NetTCPConnection | Where-Object State -eq 'Established'

# File system browsing
Get-ChildItem -Path C:\ -Force
```

---

## 🏗 Architecture

```
PowBotV1/
├── apps/
│   ├── __init__.py          # Flask app factory
│   ├── config.py             # Configuration settings
│   ├── authentication/       # Login, registration, OAuth
│   ├── home/
│   │   ├── routes.py         # Main application routes
│   │   └── master/
│   │       └── stub/         # PowerShell templates
│   │           ├── PShell.ps1    # Client agent template
│   │           └── Pcrypt.ps1    # Obfuscation script
│   ├── static/               # CSS, JS, images, fonts
│   └── templates/            # Jinja2 HTML templates
├── Powroute.py               # C2 API server (command routing)
├── runLocal.py               # Development server
├── runWeb.py                 # Production server with SSL
├── requirements.txt          # Python dependencies
└── README.md
```

### Communication Flow

```
┌─────────────┐         HTTPS/4000          ┌─────────────┐
│   Client    │ ◄──────────────────────────► │  Powroute   │
│  (PShell)   │    /check, /response        │   (API)     │
└─────────────┘                              └──────┬──────┘
                                                    │
                                                    │ Internal
                                                    │
┌─────────────┐         HTTPS/443           ┌──────┴──────┐
│   Browser   │ ◄──────────────────────────► │    Flask    │
│  (Admin)    │    /index, /settings        │   (Panel)   │
└─────────────┘                              └─────────────┘
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session secret | Auto-generated |
| `SQLALCHEMY_DATABASE_URI` | Database connection string | SQLite |
| `ASSETS_ROOT` | Static assets path | `/static/assets` |

### Client Configuration

The PowerShell agent supports the following configurable parameters:

| Parameter | Description |
|-----------|-------------|
| `{{URL}}` | Base64-encoded server URL |
| `{{CHECK_INTERVAL}}` | Polling interval in milliseconds |
| `{{PERSISTENCE}}` | Enable registry persistence (`$true`/`$false`) |

---

## 📦 Dependencies

### Core
- **Flask** – Web framework
- **Flask-SQLAlchemy** – Database ORM
- **Flask-Login** – User session management
- **Flask-WTF** – Form handling and CSRF protection
- **Flask-CORS** – Cross-origin resource sharing
- **Gevent** – Async WSGI server

### Authentication
- **Flask-Dance** – OAuth integration
- **email-validator** – Email validation

### Performance
- **Flask-Minify** – HTML/JS/CSS minification
- **Flask-Migrate** – Database migrations

---

## ⚠️ Disclaimer

> **This tool is intended for authorized security testing, red team operations, and educational purposes only.**

- Always obtain proper authorization before deployment
- Ensure compliance with local laws and regulations
- The authors are not responsible for misuse of this software
- Use responsibly and ethically

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

<p align="center">
  Made with ⚡ by Red Teamers
</p>
