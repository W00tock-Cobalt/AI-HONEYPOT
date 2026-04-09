# 🍯 OpenAI API Honeypot

A production-grade honeypot that mimics the OpenAI API to capture and analyze attacks on AI infrastructure.

**Purpose**: Security research and threat intelligence gathering on API abuse patterns.

## Features

- **Full OpenAI API Compatibility**: Implements all major endpoints with realistic responses
- **Comprehensive Logging**: Captures every detail of incoming requests
- **Geolocation**: Maps attack sources using MaxMind GeoLite2
- **Auto-Classification**: Categorizes visitors (scanner, credential-stuffer, prompt-harvester, etc.)
- **Admin Dashboard**: Real-time monitoring with world map visualization
- **Always HTTP 200**: Never reveals it's a honeypot through error responses
- **Timing Obfuscation**: Random response delays to prevent fingerprinting

## Endpoints Implemented

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | Chat completions (streaming supported) |
| `/v1/completions` | POST | Legacy completions |
| `/v1/embeddings` | POST | Text embeddings |
| `/v1/models` | GET | List available models |
| `/v1/models/{id}` | GET | Retrieve specific model |
| `/v1/images/generations` | POST | Image generation |
| `/v1/usage` | GET | Usage statistics |
| `/v1/dashboard/billing/usage` | GET | Billing data |
| `/v1/organization/api-keys` | GET | **HIGH VALUE LURE** - Fake API keys |

## Quick Start (Local Testing)

```bash
# Clone and setup
cd honeypot
chmod +x setup.sh
./setup.sh

# Edit configuration
nano .env

# Run
source venv/bin/activate
python main.py
```

Access the admin dashboard at `http://localhost:8000/admin`

## Production Deployment (Ubuntu 24.04)

### 1. Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3.11 python3.11-venv python3-pip nginx certbot python3-certbot-nginx

# Create honeypot user
sudo useradd -r -s /bin/false honeypot

# Create installation directory
sudo mkdir -p /opt/honeypot
sudo chown honeypot:honeypot /opt/honeypot
```

### 2. Install Honeypot

```bash
# Copy files to server (from your local machine)
scp -r honeypot/* user@server:/opt/honeypot/

# On the server
cd /opt/honeypot
sudo -u honeypot chmod +x setup.sh
sudo -u honeypot ./setup.sh
```

### 3. Configure Environment

```bash
sudo -u honeypot nano /opt/honeypot/.env
```

Set these values:
```env
ADMIN_USERNAME=your-admin-username
ADMIN_PASSWORD=your-secure-password-here
JWT_SECRET=<generated-by-setup>
MAXMIND_LICENSE_KEY=your-maxmind-key
```

### 4. Setup Systemd Service

```bash
# Copy service file
sudo cp /opt/honeypot/honeypot.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable honeypot
sudo systemctl start honeypot

# Check status
sudo systemctl status honeypot
sudo journalctl -u honeypot -f
```

### 5. Configure Nginx

```bash
# Copy nginx config
sudo cp /opt/honeypot/nginx.conf /etc/nginx/sites-available/honeypot

# Edit domain name
sudo nano /etc/nginx/sites-available/honeypot
# Change api.yourdomain.com to your actual domain

# Enable site
sudo ln -s /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

### 6. SSL with Certbot

```bash
# Get certificate
sudo certbot --nginx -d api.yourdomain.com

# Auto-renewal is configured automatically
sudo systemctl status certbot.timer
```

### 7. Firewall Configuration

```bash
# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## Seeding Strategies

The honeypot is most effective when attackers discover it. Here are proven seeding techniques:

### 1. GitHub "Leaked" .env File

Create a fake repository with a "leaked" environment file:

```bash
# In a new git repo
echo "OPENAI_API_KEY=sk-proj-$(openssl rand -hex 24)" > .env
echo "OPENAI_BASE_URL=https://api.yourdomain.com/v1" >> .env
git add .env
git commit -m "add config"
git push
# Then "accidentally" push, wait, then delete
```

Attackers monitor GitHub for exposed secrets and will discover the base URL.

### 2. Pastebin/Gist Seeds

Create pastes that look like developer notes:

```
# My OpenAI setup notes
API_KEY: sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Base URL: https://api.yourdomain.com/v1
Working great for my chatbot project!
```

### 3. HuggingFace Spaces

Create a demo space with the honeypot URL in the code:

```python
import openai
client = openai.OpenAI(
    api_key="sk-proj-demo",
    base_url="https://api.yourdomain.com/v1"
)
```

### 4. Stack Overflow / Forums

Answer questions about OpenAI API issues with your endpoint mentioned.

### 5. Shodan/Censys Visibility

The honeypot responds to HTTP requests on standard ports, making it discoverable by internet scanners.

## Blog Methodology Notes

### Part 1: Infrastructure Setup

For your writeup, document:

1. **Hypothesis**: What types of attacks do you expect to see on AI APIs?
   - Stolen credential testing
   - Prompt injection attempts
   - Rate limit probing
   - Model enumeration

2. **Metrics to Track**:
   - Time to first hit after seeding
   - Geographic distribution of attacks
   - Most targeted endpoints
   - API key patterns (real stolen vs. test values)
   - Classification breakdown over time

3. **Ethical Considerations**:
   - Honeypot disclosure: This is a research honeypot for documenting attacks
   - Data handling: IP addresses and request data are logged for research
   - No actual AI processing occurs
   - Fake API keys returned are clearly honeypot tokens

4. **Data Collection Period**:
   - Recommended: 30-90 days for meaningful data
   - Document any seeding activities with timestamps

### Analysis Queries

Export data and run analysis:

```python
import pandas as pd
import json

# Load export
with open('honeypot_export.json') as f:
    data = json.load(f)

df = pd.DataFrame(data)

# Top source countries
print(df['country_code'].value_counts().head(10))

# Classification breakdown
print(df['classification'].value_counts())

# Most common API keys tried
print(df['api_key'].value_counts().head(20))

# Requests over time
df['date'] = pd.to_datetime(df['timestamp']).dt.date
print(df.groupby('date').size())
```

## Maintenance

### Update GeoIP Database Monthly

```bash
cd /opt/honeypot
sudo -u honeypot ./download_geoip.sh
sudo systemctl restart honeypot
```

### View Logs

```bash
# Application logs
sudo journalctl -u honeypot -f

# Nginx access logs
sudo tail -f /var/log/nginx/honeypot_access.log
```

### Backup Data

```bash
# Export from admin dashboard or directly
sqlite3 /opt/honeypot/honeypot.db ".dump" > backup.sql
```

## Security Considerations

- **Admin Dashboard**: Always use strong credentials and consider IP restrictions in nginx
- **Database**: SQLite file should be protected (honeypot user only)
- **Fake API Keys**: Keys returned by `/v1/organization/api-keys` are tracked - any use confirms credential theft
- **Rate Limiting**: Optional in nginx config - disable to capture maximum data

## Contributing

This is a security research tool. Contributions welcome for:
- Additional endpoint implementations
- Improved classification heuristics
- Dashboard enhancements
- Analysis tooling

## License

MIT License - For security research purposes only.

## Disclaimer

This tool is designed for defensive security research. The operator is responsible for:
- Compliance with local laws regarding honeypots
- Ethical handling of collected data
- Clear documentation of research purposes
