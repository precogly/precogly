# Self-Hosting Precogly on AWS with Docker Compose, Caddy, and Remote MCP

Deploy Precogly on a single EC2 instance with TLS and a publicly reachable MCP endpoint. This setup is suitable for workshops, demos, and small-team deployments.

## What you get

| Component | Role |
| --- | --- |
| EC2 (t3.medium) | Hosts everything |
| Docker Compose | Runs Postgres, Django/Gunicorn, Nginx (frontend), and Caddy |
| Caddy | Reverse proxy with automatic Let's Encrypt TLS |
| MCP endpoint | OAuth-protected, reachable by Claude.ai, Claude Code, and other MCP clients |

## Prerequisites

- An AWS account
- A domain you control (this guide uses `precogly.example.com` as an example)
- An SSH key pair

## 1. Launch an EC2 instance

1. Open the EC2 console and select a region close to your audience (e.g. `eu-central-1` for Europe).
2. Click **Launch instances** with these settings:

| Setting | Value |
| --- | --- |
| Name | `precogly-workshop` (or any name) |
| AMI | Ubuntu Server 26.04 LTS |
| Instance type | `t3.medium` (2 vCPU, 4 GiB RAM) |
| Key pair | Select or create one (.pem format for macOS/Linux) |
| Security group | Allow SSH (22), HTTP (80), HTTPS (443) from anywhere |
| Storage | 20 GiB gp3 |

3. Launch the instance.

If you downloaded a new key pair, restrict its permissions:

```bash
chmod 400 ~/Downloads/your-key.pem
```

## 2. Allocate an Elastic IP

An Elastic IP gives your instance a fixed public address that survives reboots.

1. Go to **EC2 > Network & Security > Elastic IPs**.
2. Click **Allocate Elastic IP address**, then **Allocate**.
3. Select it, then **Actions > Associate Elastic IP address**.
4. Pick your instance and click **Associate**.

Note the IP address. You will need it for DNS and SSH.

## 3. Point your domain at the instance

In your DNS provider, add an A record:

| Type | Host | Value |
| --- | --- | --- |
| A | `demo` (or your chosen subdomain) | Your Elastic IP |

DNS propagation can take a few minutes to a couple of hours.

## 4. SSH in and install Docker

```bash
ssh -i ~/Downloads/your-key.pem ubuntu@<your-elastic-ip>
sudo apt update && sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker ubuntu
exit
```

Log back in for the group change to take effect:

```bash
ssh -i ~/Downloads/your-key.pem ubuntu@<your-elastic-ip>
```

## 5. Clone the repo

```bash
git clone https://github.com/precogly/precogly.git
cd precogly
```

## 6. Create the environment file

Generate two secrets:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(50))"
python3 -c "import secrets; print(secrets.token_urlsafe(50))"
```

Create `.env` with those values (replace the placeholders):

```bash
cat > .env << 'EOF'
SECRET_KEY=<first-secret>
POSTGRES_PASSWORD=<second-secret>
POSTGRES_USER=precogly
POSTGRES_DB=precogly
ALLOWED_HOSTS=precogly.example.com,<your-elastic-ip>
CORS_ALLOWED_ORIGINS=https://precogly.example.com
FRONTEND_URL=https://precogly.example.com
MCP_RESOURCE_URL=https://precogly.example.com/mcp
MCP_ISSUER_URL=https://precogly.example.com
EOF
```

Replace `precogly.example.com` with your actual domain throughout.

## 7. Create the Caddyfile

Caddy sits in front of everything, terminates TLS, and routes requests to the backend or frontend.

```bash
cat > Caddyfile << 'EOF'
precogly.example.com {
    handle /api/* {
        reverse_proxy backend:8000 {
            header_up Host {host}
        }
    }
    handle /admin/* {
        reverse_proxy backend:8000 {
            header_up Host {host}
        }
    }
    handle /media/* {
        reverse_proxy backend:8000 {
            header_up Host {host}
        }
    }
    handle /mcp {
        reverse_proxy backend:8000 {
            header_up Host {host}
        }
    }
    handle /o/* {
        reverse_proxy backend:8000 {
            header_up Host {host}
        }
    }
    handle /.well-known/* {
        reverse_proxy backend:8000 {
            header_up Host {host}
        }
    }
    handle {
        reverse_proxy frontend:80
    }
}
EOF
```

Replace `precogly.example.com` with your domain.

## 8. Create the workshop compose file

This is a standalone compose file that runs the full stack in production mode with Caddy in front.

```bash
cat > docker-compose.workshop.yml << 'EOF'
services:
  db:
    image: postgres:16-alpine
    container_name: precogly-postgres
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-precogly}
      POSTGRES_USER: ${POSTGRES_USER:-precogly}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-precogly} -d ${POSTGRES_DB:-precogly}"]
      interval: 5s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: .
      dockerfile: backend/Dockerfile
      target: prod
    container_name: precogly-backend
    environment:
      DATABASE_URL: postgres://${POSTGRES_USER:-precogly}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB:-precogly}
      DJANGO_SETTINGS_MODULE: config.settings.workshop
      SECRET_KEY: ${SECRET_KEY}
      ALLOWED_HOSTS: ${ALLOWED_HOSTS:-localhost}
      CORS_ALLOWED_ORIGINS: ${CORS_ALLOWED_ORIGINS:-http://localhost}
      FRONTEND_URL: ${FRONTEND_URL:-http://localhost}
      MCP_RESOURCE_URL: ${MCP_RESOURCE_URL}
      MCP_ISSUER_URL: ${MCP_ISSUER_URL}
    depends_on:
      db:
        condition: service_healthy

  frontend:
    build:
      context: ./frontend
      target: prod
    container_name: precogly-frontend
    depends_on:
      - backend

  caddy:
    image: caddy:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
    dns:
      - 8.8.8.8
      - 8.8.4.4
    depends_on:
      - frontend
      - backend

volumes:
  postgres_data:
  caddy_data:
EOF
```

## 9. Create the workshop settings file

The production settings enable `SECURE_SSL_REDIRECT`, which causes redirect loops behind a TLS-terminating proxy. The workshop settings file adds the proxy header that tells Django the connection is already secure.

```bash
cat > backend/config/settings/workshop.py << 'EOF'
from .production import *  # noqa: F401, F403

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
EOF
```

## 10. Start the stack

```bash
docker compose -f docker-compose.workshop.yml up --build -d
```

Wait for all containers to start, then seed the database with demo data:

```bash
docker compose -f docker-compose.workshop.yml exec backend python manage.py seed
```

## 11. Verify

Open `https://precogly.example.com` in a browser and log in:

| Email | Password |
| --- | --- |
| `admin@precogly.dev` | `admin123` |

## 12. Connect an MCP client

### Claude.ai

1. Go to **Settings > Connectors > Add custom connector**.
2. Name: `Precogly`, URL: `https://precogly.example.com/mcp`.
3. Keep the detected defaults (Sign in now, Register automatically).
4. Authorize with `admin@precogly.dev` / `admin123`.

### Claude Code

Add the server from the command line:

```bash
claude mcp add --transport http precogly https://precogly.example.com/mcp
```

Or add it to the `.mcp.json` file in your project:

```json
{
  "mcpServers": {
    "precogly": {
      "type": "http",
      "url": "https://precogly.example.com/mcp"
    }
  }
}
```

Then run `/mcp` inside Claude Code and choose **Authenticate** to sign in through your browser.

### Other MCP clients

Any client that supports the MCP remote transport can connect to `https://precogly.example.com/mcp`. The endpoint uses OAuth 2.0 with dynamic client registration (RFC 7591).

## Updating

After pushing changes to the repo, SSH in and pull:

```bash
cd ~/precogly
git pull
docker compose -f docker-compose.workshop.yml up --build -d
```

## Stopping and cost management

Stop the instance when not in use to avoid compute charges:

```bash
# From the AWS console: select instance > Instance state > Stop instance
```

You only pay for EBS storage (~$1.60/mo for 20 GiB) while stopped. The Elastic IP is free while attached to a running instance but costs ~$3.60/mo while the instance is stopped. Release the Elastic IP if you stop for an extended period (you will get a new IP on next allocation).

## Troubleshooting

**Backend not starting:** Check logs with `docker compose -f docker-compose.workshop.yml logs backend`. Common causes: wrong `POSTGRES_PASSWORD` (if the volume was created with a different password, run `docker compose -f docker-compose.workshop.yml down -v` to reset), missing `SECRET_KEY`.

**HTTPS not working:** Check Caddy logs with `docker compose -f docker-compose.workshop.yml logs caddy`. Caddy needs ports 80 and 443 open in the security group, and the DNS record must resolve to your Elastic IP for Let's Encrypt validation.

**MCP connection fails with 502:** The backend container is not running. Check `docker compose -f docker-compose.workshop.yml ps` and backend logs.

**MCP "Invalid Host header":** The MCP SDK's DNS rebinding protection is rejecting the host. Ensure the `transport_security` parameter is set to disable DNS rebinding protection in `mcp/src/precogly_mcp/server.py` (see the `streamable_http_app` call in the `asgi_app` function).

**Redirect loop on login:** The `SECURE_PROXY_SSL_HEADER` setting is missing. Ensure `DJANGO_SETTINGS_MODULE` is set to `config.settings.workshop` (not `config.settings.production`) in the compose file.
