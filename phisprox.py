#!/usr/bin/env python3
"""
PhisPox - Production Email Phishing Detector
Created by: Kaif Shaikh
Deploy on Linux with: python3 phispox.py --dashboard
"""

import sys
import re
import email
from email import policy
from urllib.parse import urlparse
import argparse
import json
import os
from datetime import datetime
import sqlite3

# Flask for web dashboard
try:
    from flask import Flask, render_template_string, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("⚠️  Flask not installed. Install with: pip3 install flask")

# Gmail API
try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    import base64
    GMAIL_AVAILABLE = True
except ImportError:
    GMAIL_AVAILABLE = False

# Notifications
try:
    import requests as req_lib
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class Database:
    """SQLite database for scan results"""
    def __init__(self, db_path='phispox.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                sender TEXT,
                subject TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                indicators TEXT
            )
        ''')
        conn.commit()
        conn.close()
    
    def save_scan(self, sender, subject, result):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO scans (timestamp, sender, subject, risk_score, risk_level, indicators)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            sender, subject,
            result['risk_score'],
            result['risk_level'],
            json.dumps(result['indicators'])
        ))
        conn.commit()
        conn.close()
    
    def get_recent_scans(self, limit=50):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,))
        results = c.fetchall()
        conn.close()
        
        return [{
            'id': r[0], 'timestamp': r[1], 'sender': r[2],
            'subject': r[3], 'risk_score': r[4], 'risk_level': r[5],
            'indicators': json.loads(r[6])
        } for r in results]
    
    def get_stats(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level')
        results = c.fetchall()
        conn.close()
        
        stats = {'total': 0, 'high': 0, 'medium': 0, 'low': 0}
        for level, count in results:
            stats['total'] += count
            stats[level.lower()] = count
        return stats


class PhishingDetector:
    """Core detection engine"""
    def __init__(self, db=None):
        self.phishing_keywords = [
            'verify your account', 'confirm your identity', 'suspended account',
            'unusual activity', 'urgent action required', 'click here immediately',
            'your account will be closed', 'limited time', 'act now'
        ]
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
        self.legitimate_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com'
        ]
        self.risk_score = 0
        self.indicators = []
        self.db = db

    def reset(self):
        self.risk_score = 0
        self.indicators = []

    def analyze_email_file(self, path):
        """Analyze .eml file"""
        with open(path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        return self.analyze_message(msg)

    def analyze_message(self, msg, verbose=True):
        """Analyze email message"""
        self.reset()
        
        sender = msg.get('From', 'Unknown')
        subject = msg.get('Subject', 'No Subject')
        
        if verbose:
            print(f"\n{'='*70}")
            print(f"PhisPox - Email Analysis")
            print(f"Created by: Kaif Shaikh")
            print(f"{'='*70}\n")
            print(f"📧 From: {sender}")
            print(f"📋 Subject: {subject}\n")
        
        # Run checks
        self.check_sender(sender)
        self.check_subject(subject)
        
        body = self.get_body(msg)
        if body:
            self.check_keywords(body)
            self.check_urls(body, verbose)
        
        result = self.get_result()
        
        if verbose:
            self.print_verdict()
        
        # Save to database
        if self.db:
            self.db.save_scan(sender, subject, result)
        
        return result

    def get_body(self, msg):
        """Extract email body"""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                pass
        return body

    def check_sender(self, sender):
        """Check sender for spoofing"""
        match = re.match(r'(.*?)<(.+?)>', sender)
        if match:
            display = match.group(1).strip()
            email_addr = match.group(2).strip()
            
            if '@' in display:
                self.add_indicator("Display name spoofing", 15)
            
            domain = email_addr.split('@')[-1] if '@' in email_addr else ''
            for legit in self.legitimate_domains:
                if legit in domain and legit != domain:
                    self.add_indicator(f"Lookalike domain: {domain}", 15)

    def check_subject(self, subject):
        """Check subject for urgency"""
        urgency = ['urgent', 'immediate', 'action required', 'suspended']
        for word in urgency:
            if word in subject.lower():
                self.add_indicator(f"Urgency tactic: {word}", 8)
                break
        
        if subject.count('!') >= 2:
            self.add_indicator("Excessive punctuation", 5)

    def check_keywords(self, body):
        """Check for phishing keywords"""
        found = []
        body_lower = body.lower()
        for keyword in self.phishing_keywords:
            if keyword in body_lower:
                found.append(keyword)
        
        if found:
            self.add_indicator(f"Phishing keywords: {len(found)} found", len(found) * 5)

    def check_urls(self, body, verbose=True):
        """Check URLs"""
        urls = re.findall(r'http[s]?://[^\s]+', body)
        
        if verbose and urls:
            print(f"🔗 Found {len(urls)} URL(s)\n")
        
        for url in urls[:5]:
            domain = urlparse(url).netloc
            
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                self.add_indicator(f"IP address URL: {domain}", 15)
            
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    self.add_indicator(f"Suspicious TLD: {tld}", 10)

    def add_indicator(self, msg, score):
        """Add indicator"""
        self.indicators.append(msg)
        self.risk_score += score

    def get_result(self):
        """Get analysis result"""
        if self.risk_score >= 50:
            level, verdict = "HIGH", "🚨 HIGH RISK - Likely Phishing"
        elif self.risk_score >= 25:
            level, verdict = "MEDIUM", "⚠️  MEDIUM RISK - Suspicious"
        else:
            level, verdict = "LOW", "✅ LOW RISK - Appears Legitimate"
        
        return {
            'risk_score': self.risk_score,
            'risk_level': level,
            'verdict': verdict,
            'indicators': self.indicators
        }

    def print_verdict(self):
        """Print analysis results"""
        print(f"{'='*70}")
        print("ANALYSIS RESULTS")
        print(f"{'='*70}\n")
        
        if self.indicators:
            print("⚠️  Indicators Found:\n")
            for ind in self.indicators:
                print(f"   • {ind}")
            print()
        
        print(f"📊 Risk Score: {self.risk_score}/100")
        result = self.get_result()
        print(f"🎯 Verdict: {result['verdict']}\n")
        print(f"{'='*70}\n")


class GmailScanner:
    """Gmail integration"""
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    
    def __init__(self, detector):
        self.service = None
        self.detector = detector
    
    def authenticate(self):
        """Authenticate with Gmail"""
        if not GMAIL_AVAILABLE:
            print("❌ Install: pip3 install google-auth-oauthlib google-api-python-client")
            return False
        
        creds = None
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', self.SCOPES)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists('credentials.json'):
                    print("❌ Need credentials.json from Google Cloud Console")
                    return False
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', self.SCOPES)
                creds = flow.run_local_server(port=0)
            
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
        
        self.service = build('gmail', 'v1', credentials=creds)
        print("✅ Gmail authenticated!\n")
        return True
    
    def scan_inbox(self, max_results=10):
        """Scan Gmail inbox"""
        if not self.service:
            return
        
        try:
            results = self.service.users().messages().list(
                userId='me', maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            print(f"📨 Scanning {len(messages)} emails...\n")
            
            suspicious = 0
            for msg_info in messages:
                msg = self.service.users().messages().get(
                    userId='me', id=msg_info['id'], format='raw'
                ).execute()
                
                msg_str = base64.urlsafe_b64decode(msg['raw'].encode('ASCII'))
                email_msg = email.message_from_bytes(msg_str, policy=policy.default)
                
                result = self.detector.analyze_message(email_msg, verbose=False)
                
                sender = email_msg.get('From', 'Unknown')[:50]
                subject = email_msg.get('Subject', 'No Subject')[:50]
                
                print(f"📧 {sender}")
                print(f"🎯 {result['verdict']} ({result['risk_score']}/100)\n")
                
                if result['risk_level'] in ['HIGH', 'MEDIUM']:
                    suspicious += 1
            
            print(f"{'='*70}")
            print(f"🎯 Found {suspicious}/{len(messages)} suspicious emails")
            print(f"{'='*70}\n")
        except Exception as e:
            print(f"❌ Error: {e}")


# Flask Web Dashboard
app = Flask(__name__)
db = Database()
detector = PhishingDetector(db)

DASHBOARD_HTML = '''<!DOCTYPE html>
<html><head><title>PhisPox Dashboard</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);padding:20px;min-height:100vh}
.container{max-width:1200px;margin:0 auto}
.header{background:#fff;padding:30px;border-radius:15px;box-shadow:0 10px 30px rgba(0,0,0,0.2);margin-bottom:20px;text-align:center}
.header h1{color:#667eea;font-size:3em;margin-bottom:10px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:20px}
.stat-card{background:#fff;padding:20px;border-radius:10px;text-align:center;box-shadow:0 5px 15px rgba(0,0,0,0.1)}
.stat-card h3{color:#666;font-size:0.9em;margin-bottom:10px}
.stat-card .num{font-size:2.5em;font-weight:bold}
.stat-card.high .num{color:#e74c3c}
.stat-card.medium .num{color:#f39c12}
.stat-card.low .num{color:#27ae60}
.stat-card.total .num{color:#667eea}
.section{background:#fff;padding:20px;border-radius:10px;box-shadow:0 5px 15px rgba(0,0,0,0.1)}
.section h2{color:#667eea;margin-bottom:15px;padding-bottom:10px;border-bottom:2px solid #667eea}
.scan-item{padding:15px;margin-bottom:10px;border-left:4px solid #ddd;background:#f8f9fa;border-radius:5px}
.scan-item.high{border-left-color:#e74c3c}
.scan-item.medium{border-left-color:#f39c12}
.scan-item.low{border-left-color:#27ae60}
.scan-header{display:flex;justify-between;align-items:center;margin-bottom:10px}
.scan-score{padding:5px 15px;border-radius:20px;color:#fff;font-weight:bold;font-size:0.9em}
.scan-score.high{background:#e74c3c}
.scan-score.medium{background:#f39c12}
.scan-score.low{background:#27ae60}
.scan-subject{color:#666;font-style:italic;margin-bottom:5px;font-size:0.9em}
.scan-indicators{color:#e74c3c;font-size:0.85em;margin-top:10px}
</style>
</head><body>
<div class="container">
<div class="header">
<h1>🛡️ PhisPox</h1>
<p>Email Phishing Detection Suite</p>
<p style="font-size:0.8em;color:#999;margin-top:5px">Created by Kaif Shaikh</p>
</div>
<div class="stats" id="stats">
<div class="stat-card total"><h3>Total Scans</h3><div class="num" id="total">0</div></div>
<div class="stat-card high"><h3>High Risk</h3><div class="num" id="high">0</div></div>
<div class="stat-card medium"><h3>Medium Risk</h3><div class="num" id="medium">0</div></div>
<div class="stat-card low"><h3>Low Risk</h3><div class="num" id="low">0</div></div>
</div>
<div class="section">
<h2>Recent Email Scans</h2>
<div id="scans"></div>
</div>
</div>
<script>
function loadData(){
fetch('/api/stats').then(r=>r.json()).then(d=>{
document.getElementById('total').textContent=d.total;
document.getElementById('high').textContent=d.high;
document.getElementById('medium').textContent=d.medium;
document.getElementById('low').textContent=d.low;
});
fetch('/api/scans').then(r=>r.json()).then(scans=>{
let html='';
scans.forEach(s=>{
let level=s.risk_level.toLowerCase();
html+=`<div class="scan-item ${level}">
<div class="scan-header">
<div style="flex:1"><strong>${s.sender}</strong></div>
<div class="scan-score ${level}">${s.risk_score}/100</div>
</div>
<div class="scan-subject">${s.subject}</div>`;
if(s.indicators.length>0){
html+=`<div class="scan-indicators">⚠️ ${s.indicators.slice(0,2).join(', ')}</div>`;
}
html+=`</div>`;
});
document.getElementById('scans').innerHTML=html||'<p style="text-align:center;color:#999">No scans yet</p>';
});
}
loadData();
setInterval(loadData,5000);
</script>
</body></html>'''

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/stats')
def api_stats():
    return jsonify(db.get_stats())

@app.route('/api/scans')
def api_scans():
    return jsonify(db.get_recent_scans(20))


def main():
    parser = argparse.ArgumentParser(
        description='PhisPox - Email Phishing Detector by Kaif Shaikh',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 phispox.py email.eml              # Analyze .eml file
  python3 phispox.py --gmail-setup          # Setup Gmail
  python3 phispox.py --scan-gmail           # Scan Gmail
  python3 phispox.py --dashboard            # Start web dashboard
        '''
    )
    
    parser.add_argument('email_file', nargs='?', help='Email file (.eml)')
    parser.add_argument('--gmail-setup', action='store_true', help='Setup Gmail API')
    parser.add_argument('--scan-gmail', action='store_true', help='Scan Gmail inbox')
    parser.add_argument('-n', '--num', type=int, default=10, help='Number of emails to scan')
    parser.add_argument('--dashboard', action='store_true', help='Start web dashboard')
    parser.add_argument('--port', type=int, default=5000, help='Dashboard port')
    parser.add_argument('-v', '--version', action='version', version='PhisPox v2.0 by Kaif Shaikh')
    
    args = parser.parse_args()
    
    # Gmail modes
    if args.gmail_setup or args.scan_gmail:
        scanner = GmailScanner(detector)
        if scanner.authenticate():
            if args.scan_gmail:
                scanner.scan_inbox(args.num)
    
    # Dashboard mode
    elif args.dashboard:
        if not FLASK_AVAILABLE:
            print("❌ Install Flask: pip3 install flask")
            return
        print(f"\n🌐 PhisPox Dashboard starting...")
        print(f"📊 Open: http://localhost:{args.port}")
        print(f"Created by: Kaif Shaikh\n")
        app.run(host='0.0.0.0', port=args.port, debug=False)
    
    # File analysis mode
    elif args.email_file:
        detector.analyze_email_file(args.email_file)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
