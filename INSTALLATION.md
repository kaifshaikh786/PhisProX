# 📦 PhisPox Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip3 package manager
- Git

## Linux Installation (Ubuntu/Debian/Parrot OS)

### Step 1: Install Dependencies
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip python3-venv git -y
```

### Step 2: Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/phisprox.git
cd phisprox
```

### Step 3: Setup Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# You should see (venv) in your prompt
```

### Step 4: Install Python Packages
```bash
pip install -r requirements.txt
```

### Step 5: Verify Installation
```bash
python3 phispox.py --version
# Expected output: PhisPox v2.0 by Kaif Shaikh
```

## Windows Installation
```powershell
# Install Python from python.org
# Then in PowerShell:

git clone https://github.com/YOUR_USERNAME/phisprox.git
cd phisprox
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python phispox.py --version
```

## macOS Installation
```bash
# Install Homebrew if needed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python3 git

# Clone and setup
git clone https://github.com/YOUR_USERNAME/phisprox.git
cd phisprox
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 phispox.py --version
```

## Gmail Integration Setup (Optional)

### Step 1: Google Cloud Console

1. Go to: https://console.cloud.google.com/
2. Create new project: "PhisPox"
3. Enable Gmail API
4. Create OAuth 2.0 credentials (Desktop app)
5. Download as `credentials.json`

### Step 2: Place Credentials
```bash
# Copy credentials.json to phisprox folder
cp ~/Downloads/credentials.json ~/phisprox/
```

### Step 3: Authenticate
```bash
python3 phispox.py --gmail-setup
# Follow browser prompts to authorize
```

## Quick Launch Setup

### Create Alias (Linux/macOS)
```bash
echo 'alias phispox="cd ~/phisprox && source venv/bin/activate"' >> ~/.bashrc
source ~/.bashrc

# Usage:
phispox
python3 phispox.py --dashboard
```

### Global Command
```bash
sudo nano /usr/local/bin/phispox
```

Paste:
```bash
#!/bin/bash
cd ~/phisprox && source venv/bin/activate && python3 ~/phisprox/phispox.py "$@"
```
```bash
sudo chmod +x /usr/local/bin/phispox

# Usage from anywhere:
phispox --dashboard
phispox --scan-gmail
```

## Troubleshooting

### "pip3 not found"
```bash
sudo apt install python3-pip -y
```

### "externally managed environment" (Debian/Parrot)
```bash
# Use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### "Module not found"
```bash
# Make sure venv is activated
source venv/bin/activate
pip install -r requirements.txt
```

## Updating PhisPox
```bash
cd ~/phisprox
git pull origin main
source venv/bin/activate
pip install -r requirements.txt --upgrade
```

## Uninstallation
```bash
# Remove PhisPox
rm -rf ~/phisprox

# Remove alias
nano ~/.bashrc
# Delete the phispox alias line
source ~/.bashrc
```
