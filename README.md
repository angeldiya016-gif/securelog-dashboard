# 🛡️ SecureLog AI Dashboard

[![Build and Test Docker Image](https://github.com/angeldiya016-gif/securelog-dashboard/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/angeldiya016-gif/securelog-dashboard/actions/workflows/ci-cd.yml)
[![Python](https://img.shields.io/badge/Python-3.10-blue?style=flat&logo=python)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?style=flat&logo=streamlit)](https://streamlit.io/)

A professional, automated Security Log Analysis Dashboard built for Blue Team operations and SOC analysts. It parses security logs, detects brute-force patterns, and visualizes threats in real-time.

![Dashboard Preview](https://via.placeholder.com/800x400/1E1E2E/FFFFFF?text=SecureLog+AI+Dashboard+Preview)

## ✨ Key Features
- 🔍 **Automated Log Parsing**: Instantly analyzes CSV log files for security events.
- 🚨 **Brute Force Detection**: Automatically flags IP addresses with multiple failed login attempts.
- 📊 **Interactive Visualizations**: Beautiful, real-time charts powered by Plotly.
- 📥 **One-Click Reporting**: Export analyzed data directly to CSV for further investigation.
- 🐳 **Dockerized**: Ready to deploy anywhere with a single Docker command.
- 🔄 **CI/CD Enabled**: Automated testing and building via GitHub Actions.

## 🛠️ Tech Stack
| Category | Technologies |
|----------|-------------|
| **Backend & Logic** | Python, Pandas, Regex |
| **Frontend / UI** | Streamlit, Plotly |
| **DevOps & Cloud** | Docker, GitHub Actions, Git |
| **Security Focus** | Log Analysis, Threat Detection, Blue Team Ops |

## 🚀 Quick Start

### Option 1: Local Setup
\`\`\`bash
# Clone the repository
git clone https://github.com/angeldiya016-gif/securelog-dashboard.git
cd securelog-dashboard

# Create and activate a virtual environment (or use conda)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
\`\`\`

### Option 2: Docker Setup (Recommended)
\`\`\`bash
# Build the Docker image
docker build -t securelog-dashboard .

# Run the container
docker run -p 8501:8501 securelog-dashboard
\`\`\`
*Access the dashboard at: http://localhost:8501*

## 📚 How to Use
1. Open the dashboard in your browser.
2. (Optional) Upload a `.csv` file containing security logs (Format: \`timestamp, event, ip, user\`).
3. The dashboard will automatically parse the data, highlight suspicious IPs, and generate a visual threat overview.
4. Click "Download Full Log Report" to export the findings.

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/angeldiya016-gif/securelog-dashboard/issues).

## 📄 License
This project is licensed under the MIT License.

---
*Built with ❤️ by [Angel Diya](https://github.com/angeldiya016-gif) | Open to DevSecOps & Security Engineering opportunities.*
