#!/bin/bash

# Archive Mastodon Installation Script
# Based on weewxstats2social install.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
   exit 1
fi

print_status "Starting Archive Mastodon installation..."

# Check prerequisites
print_status "Checking prerequisites..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go 1.19 or later."
    print_status "Visit https://golang.org/doc/install for installation instructions."
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
print_success "Found Go version: $GO_VERSION"

# Check if git is installed
if ! command -v git &> /dev/null; then
    print_error "Git is not installed. Please install git."
    exit 1
fi

print_success "Git is installed"

# Create installation directory
INSTALL_DIR="/opt/archive-mastodon"
SERVICE_USER="archivebot"

print_status "Creating installation directory: $INSTALL_DIR"

# Create service user if it doesn't exist
if ! id "$SERVICE_USER" &>/dev/null; then
    print_status "Creating service user: $SERVICE_USER"
    sudo useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
    print_success "Created service user: $SERVICE_USER"
else
    print_success "Service user $SERVICE_USER already exists"
fi

# Create installation directory
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# Build the application
print_status "Building the application..."

# Check if we're in the right directory
if [ ! -f "main.go" ]; then
    print_error "main.go not found. Please run this script from the archive-mastodon directory."
    exit 1
fi

# Install dependencies
print_status "Installing Go dependencies..."
go mod tidy

# Build the application
print_status "Compiling the application..."
go build -o archive-mastodon main.go

if [ ! -f "archive-mastodon" ]; then
    print_error "Build failed. Please check the error messages above."
    exit 1
fi

print_success "Application built successfully"

# Copy files to installation directory
print_status "Installing files to $INSTALL_DIR..."

# Use move-then-overwrite technique for executable
if [ -f "$INSTALL_DIR/archive-mastodon" ]; then
    print_status "Updating executable using move-then-overwrite technique..."
    sudo mv "$INSTALL_DIR/archive-mastodon" "$INSTALL_DIR/archive-mastodon.old"
    sudo cp archive-mastodon "$INSTALL_DIR/"
    sudo rm "$INSTALL_DIR/archive-mastodon.old"
    print_success "Executable updated"
else
    sudo cp archive-mastodon "$INSTALL_DIR/"
    print_success "Executable installed"
fi

sudo cp README.md "$INSTALL_DIR/"

# Only copy config.json if it doesn't exist
if [ ! -f "$INSTALL_DIR/config.json" ]; then
    print_status "Creating initial config.json from example..."
    sudo cp config.json.example "$INSTALL_DIR/config.json"
    print_success "Initial config.json created"
else
    print_warning "Config file already exists at $INSTALL_DIR/config.json - preserving user configuration"
fi

# Set proper permissions
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
sudo chmod +x "$INSTALL_DIR/archive-mastodon"

print_success "Files installed successfully"

# Create systemd service file
print_status "Creating systemd service..."

SERVICE_FILE="/etc/systemd/system/archive-mastodon.service"

sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Archive Mastodon Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/archive-mastodon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

print_success "Systemd service file created"

# Reload systemd and enable service
print_status "Enabling systemd service..."

sudo systemctl daemon-reload
sudo systemctl enable archive-mastodon.service

# Check if service is already running and restart it
if sudo systemctl is-active --quiet archive-mastodon.service; then
    print_status "Service is currently running. Restarting it..."
    sudo systemctl restart archive-mastodon.service
    print_success "Service restarted successfully"
else
    print_status "Service is not currently running"
fi

print_success "Service enabled successfully"

# Create log directory
LOG_DIR="/var/log/archive-mastodon"
sudo mkdir -p "$LOG_DIR"
sudo chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"

print_success "Log directory created: $LOG_DIR"





# Final instructions
print_success "Installation completed successfully!"
echo
echo "Next steps:"
echo "1. Configure the application:"
echo "   sudo nano $INSTALL_DIR/config.json"
echo
echo "2. Start the service (if not already running):"
echo "   sudo systemctl start archive-mastodon"
echo
echo "3. Check the service status:"
echo "   sudo systemctl status archive-mastodon"
echo
echo "4. View logs:"
echo "   sudo journalctl -u archive-mastodon -f"
echo

print_warning "Remember to configure your Fediverse instance URL and credentials before starting the service!"
print_success "Note: If the service was already running, it has been automatically restarted with the new version." 