#!/bin/bash

# Simple script to archive URLs to ArchiveBox
# Usage: ./archive_url.sh "https://example.com"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <URL>"
    echo "Example: $0 \"https://example.com\""
    exit 1
fi

URL="$1"

# Build the Go tool if it doesn't exist
if [ ! -f "archive_url" ]; then
    echo "Building archive_url tool..."
    go build -o archive_url archive_url.go
fi

# Run the archive tool
./archive_url -url "$URL" 