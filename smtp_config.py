"""
SMTP Configuration for OTP Email System

To use this OTP system, you need to:

1. Set up your email credentials in environment variables:
   - SMTP_SERVER (e.g., smtp.gmail.com)
   - SMTP_PORT (e.g., 587 for TLS)
   - SMTP_USERNAME (your email address)
   - SMTP_PASSWORD (your app password)

2. For Gmail:
   - Enable 2-factor authentication
   - Generate an App Password
   - Use the App Password as SMTP_PASSWORD

3. For other providers:
   - Check their SMTP settings
   - Use appropriate server and port

Example .env file:
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
"""

import os

# SMTP Configuration
SMTP_CONFIG = {
    "server": os.getenv("SMTP_SERVER"),
    "port": int(os.getenv("SMTP_PORT")),
    "username": os.getenv("SMTP_USERNAME"),
    "password": os.getenv("SMTP_PASSWORD")
}

# OTP Configuration
OTP_CONFIG = {
    "expiry_minutes": 10,
    "length": 6
} 