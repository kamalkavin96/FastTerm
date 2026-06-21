#!/bin/sh

set -e

echo "Starting Nginx..."
nginx

echo "Starting FastTerm..."
python /app/src/main.py &
FASTAPI_PID=$!


echo "Installing/Starting Uptime Kuma..."

# Install Node.js if not already installed
if ! command -v node >/dev/null 2>&1; then
    apt-get update
    apt-get install -y curl
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
fi

# Clone Uptime Kuma if missing
if [ ! -d "/opt/uptime-kuma" ]; then
    git clone https://github.com/louislam/uptime-kuma.git /opt/uptime-kuma
fi

cd /opt/uptime-kuma

# Install dependencies
npm install

# Build frontend
npm run build

# Create persistent data directory
mkdir -p /data

# Start Uptime Kuma in background
DATA_DIR=/data PORT=3000 npm run start-server &

wait $FASTAPI_PID