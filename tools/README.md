# Archive URL Tool

A simple tool to archive URLs to ArchiveBox using credentials from the main config.json file.

## Usage

### Using the shell script (recommended)
```bash
cd tools
./archive_url.sh "https://example.com"
```

### Using the Go binary directly
```bash
cd tools
go build -o archive_url archive_url.go
./archive_url -url "https://example.com"
```

## Configuration

The tool reads ArchiveBox credentials from `../config.json`:

```json
{
  "archivebox": {
    "url": "https://archive.23.nu",
    "username": "fediarchive",
    "password": "your_password"
  }
}
```

## Features

- ✅ **Automatic authentication** - Handles login flow with CSRF token management
- ✅ **Session management** - Maintains session cookies across requests
- ✅ **Redirect handling** - Follows ArchiveBox's redirect chain properly
- ✅ **URL queuing** - Adds URLs to ArchiveBox's archiving queue
- ✅ **Error handling** - Provides clear error messages for common issues

## How it works

1. **Authentication Flow**:
   - Starts by accessing `/add/` page
   - Follows redirects to login page if not authenticated
   - Extracts CSRF token from login form
   - Submits login credentials with proper headers
   - Follows redirects to establish session

2. **URL Addition Flow**:
   - Accesses `/add/` page with authenticated session
   - Extracts CSRF token from add form
   - Submits URL with proper form data
   - Queues URL for archiving with depth=0

## Requirements

- Go 1.16 or later
- ArchiveBox instance with web interface enabled
- Valid ArchiveBox credentials in config.json

## Examples

```bash
# Archive a single URL
./archive_url.sh "https://example.com"

# Archive multiple URLs (run multiple times)
./archive_url.sh "https://github.com"
./archive_url.sh "https://stackoverflow.com"
```

## Troubleshooting

- **Login failed**: Check credentials in config.json
- **CSRF token errors**: The script handles this automatically
- **Session expired**: The script will re-authenticate automatically
- **404 errors**: Make sure the ArchiveBox URL in config.json is correct 