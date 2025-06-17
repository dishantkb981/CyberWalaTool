# 🛡️ CyberWalaTool

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey" alt="Platform">
</div>

## 📝 Description
CyberWalaTool is an advanced cybersecurity tool designed for ethical hackers and security professionals. It provides comprehensive security scanning and analysis capabilities for web applications and networks.

## 🚀 Features
- 🔍 Port Scanning
- 🌐 DNS Enumeration
- 🔐 SSL/TLS Analysis
- 🕵️‍♂️ Subdomain Discovery
- 📊 Vulnerability Assessment
- 🔒 Security Headers Check
- 📝 Detailed Reporting

## 📋 Prerequisites
- Python 3.8 or higher
- Root/Administrator privileges
- Linux/Windows operating system

## ⚙️ Installation

### Method 1: Using install.sh (Recommended)
```bash
# Clone the repository
git clone https://github.com/dishantkb981/CyberWalaTool.git

# Navigate to the directory
cd CyberWalaTool

# Make the install script executable
chmod +x install.sh

# Run the installation script as root
sudo ./install.sh
```

### Method 2: Manual Installation
```bash
# Clone the repository
git clone https://github.com/dishantkb981/CyberWalaTool.git

# Navigate to the directory
cd CyberWalaTool

# Install dependencies
sudo pip3 install -r requirements.txt
```

## 🎯 Usage

### Basic Usage
```bash
# Run as root/administrator
sudo python3 cyberwala.py example.com
```

### Advanced Usage
```bash
# Scan specific ports
sudo python3 cyberwala.py example.com -p 80,443,8080

# Enable verbose output
sudo python3 cyberwala.py example.com -v

# Save results to specific directory
sudo python3 cyberwala.py example.com -o /path/to/output
```

## 📊 Output
The tool generates detailed reports in the following formats:
- HTML reports
- JSON output
- Text-based summaries

Reports are saved in the `scan_results_[target]` directory.

## 🐳 Docker Support
You can also run the tool using Docker:
```bash
# Build the Docker image
docker build -t cyberwala .

# Run the container
docker run -it cyberwala example.com
```

## ⚠️ Disclaimer
This tool is for educational and ethical hacking purposes only. Always obtain proper authorization before scanning any target. The authors are not responsible for any misuse or damage caused by this tool.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support
For support, please open an issue in the GitHub repository.

---
<div align="center">
  Made with ❤️ by the CyberWala Team
</div>
