#!/bin/bash
#
# OpenAI API Honeypot - Setup Script
#
# This script sets up the honeypot environment:
# - Creates Python virtual environment
# - Installs dependencies
# - Downloads MaxMind GeoLite2 database
# - Creates configuration from template
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║     🍯 OpenAI API Honeypot Setup      ║"
echo "  ║       Security Research Tool          ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1-2)
REQUIRED_VERSION="3.11"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Error: Python $REQUIRED_VERSION or higher is required (found $PYTHON_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}Python $PYTHON_VERSION detected${NC}"

# Create virtual environment
echo -e "\n${YELLOW}Creating virtual environment...${NC}"
if [ -d "venv" ]; then
    echo "Virtual environment already exists, recreating..."
    rm -rf venv
fi

python3 -m venv venv
source venv/bin/activate

echo -e "${GREEN}Virtual environment created at ./venv${NC}"

# Upgrade pip
echo -e "\n${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip

# Install dependencies
echo -e "\n${YELLOW}Installing dependencies...${NC}"
pip install -r requirements.txt

echo -e "${GREEN}Dependencies installed${NC}"

# Create .env from template if not exists
echo -e "\n${YELLOW}Setting up configuration...${NC}"
if [ ! -f ".env" ]; then
    cp .env.example .env

    # Generate JWT secret
    JWT_SECRET=$(openssl rand -hex 32)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/your-256-bit-secret-here/$JWT_SECRET/" .env
    else
        sed -i "s/your-256-bit-secret-here/$JWT_SECRET/" .env
    fi

    echo -e "${GREEN}Created .env from template${NC}"
    echo -e "${YELLOW}⚠️  Please edit .env and set:${NC}"
    echo "   - ADMIN_PASSWORD (change from default)"
    echo "   - MAXMIND_LICENSE_KEY (get from maxmind.com)"
else
    echo ".env already exists, skipping..."
fi

# Download GeoLite2 database
echo -e "\n${YELLOW}Setting up GeoIP database...${NC}"

# Load .env to get MAXMIND_LICENSE_KEY
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

if [ -f "GeoLite2-City.mmdb" ]; then
    echo "GeoLite2-City.mmdb already exists"
elif [ -z "$MAXMIND_LICENSE_KEY" ] || [ "$MAXMIND_LICENSE_KEY" = "your-license-key-here" ]; then
    echo -e "${YELLOW}⚠️  MaxMind license key not set${NC}"
    echo ""
    echo "To enable geolocation:"
    echo "1. Create a free account at https://www.maxmind.com/en/geolite2/signup"
    echo "2. Generate a license key in your account"
    echo "3. Add it to .env as MAXMIND_LICENSE_KEY=your-key"
    echo "4. Run: ./download_geoip.sh"
    echo ""
    echo "Or manually download GeoLite2-City.mmdb and place it in this directory"
else
    echo "Downloading GeoLite2-City database..."

    DOWNLOAD_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

    curl -sSL "$DOWNLOAD_URL" -o geoip.tar.gz

    if [ $? -eq 0 ]; then
        tar -xzf geoip.tar.gz
        mv GeoLite2-City_*/GeoLite2-City.mmdb .
        rm -rf GeoLite2-City_* geoip.tar.gz
        echo -e "${GREEN}GeoLite2-City.mmdb downloaded successfully${NC}"
    else
        echo -e "${RED}Failed to download GeoIP database${NC}"
        echo "Please check your MAXMIND_LICENSE_KEY in .env"
    fi
fi

# Create download script for later use
cat > download_geoip.sh << 'EOFSCRIPT'
#!/bin/bash
# Download/update GeoLite2-City database
# Run this monthly to keep the database current

set -e

if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

if [ -z "$MAXMIND_LICENSE_KEY" ] || [ "$MAXMIND_LICENSE_KEY" = "your-license-key-here" ]; then
    echo "Error: MAXMIND_LICENSE_KEY not set in .env"
    exit 1
fi

echo "Downloading GeoLite2-City database..."
DOWNLOAD_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

curl -sSL "$DOWNLOAD_URL" -o geoip.tar.gz
tar -xzf geoip.tar.gz
mv GeoLite2-City_*/GeoLite2-City.mmdb .
rm -rf GeoLite2-City_* geoip.tar.gz

echo "GeoLite2-City.mmdb updated successfully"
EOFSCRIPT
chmod +x download_geoip.sh

# Create empty static directories if needed
mkdir -p static/css static/js

echo -e "\n${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}Setup complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"

echo -e "\n${YELLOW}Next steps:${NC}"
echo ""
echo "1. Edit .env and set your admin password:"
echo "   nano .env"
echo ""
echo "2. (Optional) Add MaxMind license key for geolocation"
echo ""
echo "3. Test locally:"
echo "   source venv/bin/activate"
echo "   python main.py"
echo ""
echo "4. Deploy to production:"
echo "   - Copy honeypot.service to /etc/systemd/system/"
echo "   - Copy nginx.conf to /etc/nginx/sites-available/"
echo "   - See README.md for full deployment guide"
echo ""
echo -e "${YELLOW}Admin dashboard:${NC} http://localhost:8000/admin"
echo -e "${YELLOW}Default login:${NC} admin / changeme (CHANGE THIS!)"
echo ""
