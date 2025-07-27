# Archive Mastodon

Automatically follows back Fediverse users, extracts URLs from posts, and archives them in ArchiveBox.

**Tested with GoToSocial, compatible with Mastodon.**

**GoToSocial note:** Redirect URI/Callback URL is `urn:ietf:wg:oauth:2.0:oob`

## Prerequisites

- Go 1.19+
- Fediverse instance (GoToSocial/Mastodon)
- ArchiveBox instance

## Installation

```bash
./install.sh
```

## Configuration

The application supports both JSON and YAML configuration formats. It will automatically detect and load the first available file in this order: `config.yaml`, `config.yml`, `config.json`.

### JSON Configuration

```bash
sudo nano /opt/archive-mastodon/config.json
```

```json
{
  "fediverse": {
    "instance_url": "https://your-instance.com",
    "username": "your-username",
    "password": "your-password",
    "token": "",
    "token_exp": ""
  },
  "archivebox": {
    "url": "http://localhost:8000",
    "username": "",
    "password": "",
    "tag": "fediarchive"
  },
  "settings": {
    "max_posts_per_user": 5000,
    "include_visibility": ["public", "unlisted", "private"]
  }
}
```

### YAML Configuration

```bash
sudo nano /opt/archive-mastodon/config.yaml
```

```yaml
fediverse:
  instance_url: "https://your-instance.com"
  username: "your-username"
  password: "your-password"
  token: ""
  token_exp: ""

archivebox:
  url: "http://localhost:8000"
  username: ""
  password: ""
  tag: "fediarchive"

settings:
  max_posts_per_user: 5000
  include_visibility:
    - "public"
    - "unlisted"
    - "private"
```

### Configuration Options

- **fediverse**: Fediverse instance configuration
  - `instance_url`: Your Fediverse instance URL
  - `username`: Your username/email
  - `password`: Your password
  - `token`: OAuth token (auto-generated)
  - `token_exp`: Token expiration (auto-managed)

- **archivebox**: ArchiveBox configuration
  - `url`: ArchiveBox instance URL
  - `username`: ArchiveBox admin username
  - `password`: ArchiveBox admin password
  - `tag`: Tag to apply to archived URLs (configurable)

- **settings**: Application settings
  - `max_posts_per_user`: Maximum posts to fetch per user
  - `include_visibility`: Which post visibilities to process

## Usage

```bash
sudo systemctl start archive-mastodon
sudo systemctl status archive-mastodon
sudo journalctl -u archive-mastodon -f
```

**Service management:**
```bash
sudo systemctl enable archive-mastodon  # Start on boot
sudo systemctl restart archive-mastodon # Restart service
sudo journalctl -u archive-mastodon -n 50 # Last 50 log entries
```

## API Endpoints

### Fediverse (Mastodon API)
- `POST /api/v1/apps` - OAuth app creation
- `GET /oauth/authorize` - OAuth authorization  
- `POST /oauth/token` - Token exchange
- `GET /api/v1/accounts/verify_credentials` - Account verification
- `GET /api/v1/accounts/{id}/followers` - Get followers
- `POST /api/v1/accounts/{id}/follow` - Follow user
- `GET /api/v1/timelines/home` - Home timeline

### ArchiveBox
- `POST /api/add` - Add URL for archiving 