# 📖 PhisPox Usage Guide

## Command Reference

### Basic Commands
```bash
# Show version
python3 phispox.py --version

# Show help
python3 phispox.py --help

# Analyze single email file
python3 phispox.py email.eml

# Start web dashboard
python3 phispox.py --dashboard

# Start on custom port
python3 phispox.py --dashboard --port 8080
```

### Gmail Integration
```bash
# First-time Gmail setup
python3 phispox.py --gmail-setup

# Scan last 10 emails
python3 phispox.py --scan-gmail

# Scan last 50 emails
python3 phispox.py --scan-gmail -n 50

# Scan only unread emails
python3 phispox.py --scan-unread
```

### Email Forwarding Service
```bash
# Start forwarding service
python3 phispox.py --forwarding your@email.com

# With password (not recommended)
python3 phispox.py --forwarding your@email.com --password yourpass
```

## Creating Test Emails

### Sample Phishing Email
```bash
cat > phishing_test.eml << 'EOF'
From: PayPal Security <support@paypa1-verify.tk>
To: victim@example.com
Subject: URGENT!! Account Verification Required
Date: Mon, 18 Dec 2023 10:00:00 +0000

Dear Valued Customer,

We have detected unusual activity on your PayPal account.

Click here immediately to verify:
http://192.168.1.100/paypal-secure-login

Your account will be suspended in 24 hours if you don't act now!

PayPal Security Team
