# Phishing URL Detector by WxZANA

A simple Python command-line tool that analyzes URLs and flags potential phishing indicators.

This project demonstrates basic phishing detection techniques by applying common heuristic checks used in cybersecurity investigations.

---

## Features

- Detects unusually long URLs
- Flags URLs with many subdomains
- Detects IP-address based URLs
- Checks for suspicious keywords commonly used in phishing attacks
- Generates a basic risk score

---

## Example Usage

Run the program with a URL:

```bash
python main.py https://google.com
