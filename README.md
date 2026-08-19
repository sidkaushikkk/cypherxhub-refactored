# 🛡️ CypherX - Detect Before You Regret

**CypherX** is an AI-powered cybersecurity web platform designed to detect phishing links, malicious QR codes, and suspicious files in real-time. Built specifically for modern threat environments, it utilizes multi-layer risk analysis to protect your digital identity across Web2 and Web3 ecosystems.

## ✨ Features

- 🔍 **URL Scanner**: Instantly check links against local threat intelligence databases for phishing attempts and malware.
- 📱 **QR Code Inspector**: Analyze embedded malicious payloads hidden inside static QR codes before you scan them on your devices.
- 🔬 **Payload Inspector (File Scanner)**: Scan file signatures, and generate AI-driven threat risk scores.
- 📡 **Live Threat Monitor / Command Center**: A centralized dashboard featuring dynamic chart visualizations (Chart.js) to track network risk percentages and intercept real-time threats.
- 📝 **Activity & Intel Feed**: Real-time logs for threat tracking, blacklisted domains, and vulnerabilities.
- 🎨 **Premium Cybersecurity UI**: Immersive, glassmorphism-inspired interface built with responsive HTML, modern CSS and subtle grid animations. 

## 🚀 Tech Stack

- **Frontend**: HTML5, CSS3 (Vanilla), JavaScript (Vanilla)
- **Data Visualizations**: [Chart.js](https://www.chartjs.org/) for interactive doughnut and timeline threat graphs.
- **Font & Icons**: Google Fonts (Orbitron, Rajdhani), Font Awesome 6.

## 🛠️ Installation & Setup

CypherX is built with vanilla web technologies and primarily functions natively within the browser environment. 
However, it also optionally includes some backend features via Node.js for extended threat intelligence APIs.


## 📁 Project Structure

````text
├── index.html        # Landing Home Page (with Insights/Vlogs section)
├── dashboard.html    # Main Security Command Center
├── scan-url.html     # Dedicated URL scanning utility
├── scan-qr.html      # QR Code payload inspector
├── monitor.html      # Live Intercept monitoring feed
├── activity.html     # Threat intelligence and activity logs
├── script.js         # Core application logic and modal handling
├── server.js         # Optional backend server for JSON APIs
└── style.css         # Typography, layout, and global UI components
````

## 🔮 Roadmap / Future Pipeline

- [ ] **Database Integration**: Connect to a live SQL/NoSQL backend to track historical scan data universally.
- [ ] **AI-Powered Analysis API**: Implement Python machine earning models to verify highly obfuscated links.
- [ ] **Web3 Wallet Threat Checks**: Scan EVM smart contract addresses and alert users on potential honeypots.

## 📄 Copyight & License

&copy; Sidhant Kaushik. All rights reserved. 
Designed and developed by Sidhant Kaushik.
