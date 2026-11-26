# Installation

Precogly runs as a set of Docker containers — a React frontend, a Django backend, a PostgreSQL database, and a development-only AI model forwarder. This guide walks you through getting everything running locally.

## Prerequisites

You need the following installed on your machine:

| Tool              | Minimum Version | Check with            |
| ----------------- | --------------- | --------------------- |
| **Docker**        | 20.10+          | `docker --version`    |
| **Docker Compose** | 2.0+           | `docker compose version` |
| **Git**           | 2.0+            | `git --version`       |

!!! tip "Docker Desktop"
    On macOS and Windows, [Docker Desktop](https://www.docker.com/products/docker-desktop/) includes both Docker and Docker Compose. On Linux, you may need to install the [Compose plugin](https://docs.docker.com/compose/install/linux/) separately.

## Quick Start

### 1. Clone the repository

```bash
git clone --branch v0.4.0 https://github.com/precogly/precogly.git
cd precogly
```

!!! tip "Latest stable release"
    The `--branch v0.4.0` flag checks out the latest stable release. To use the development branch instead, omit it and clone `main`.

### 2. Start the application

```bash
docker compose up --build
```

This builds and starts four containers:

| Container                    | Host port | Description                                      |
| ---------------------------- | --------- | ------------------------------------------------ |
| `precogly-frontend`          | 5173      | React development server                         |
| `precogly-backend`           | 8000      | Django API server                                |
| `precogly-postgres`          | 5432      | PostgreSQL 16 database                           |
| `precogly-lmstudio-proxy`    | None      | Development-only forwarder to a host AI provider |

On first launch, the backend automatically:

1. Runs database migrations
2. Seeds demo data: a superuser, two organizations, three demo library packs, and sample threat models

### 3. Log in

Open [http://localhost:5173](http://localhost:5173) and log in with the demo credentials:

| Field        | Value                |
| ------------ | -------------------- |
| **Email**    | `admin@precogly.dev` |
| **Password** | `admin123`           |

Two further accounts are seeded alongside it, sharing the same password. Both exist so
that role and multi-tenancy behaviour can be exercised locally, and neither is needed to
work through the product:

| Email                  | Organization      | Role          |
| ---------------------- | ----------------- | ------------- |
| `analyst@precogly.dev` | Demo Organization | Member        |
| `contoso@precogly.dev` | Contoso Financial | Security Team |

The seed prints all three as a table when it finishes, so the credentials are also in the
`docker compose up` output.

## Environment Variables

Precogly works out of the box with sensible defaults. To customize settings, copy the example environment file and edit it:

```bash
cp .env.example .env
```

### Available Variables

| Variable                 | Default                        | Description                          |
| ------------------------ | ------------------------------ | ------------------------------------ |
| `POSTGRES_DB`            | `precogly`                     | Database name                        |
| `POSTGRES_USER`          | `precogly`                     | Database user                        |
| `POSTGRES_PASSWORD`      | `precogly_dev_password`        | Database password                    |
| `SECRET_KEY`             | insecure dev key               | Django secret key                    |
| `DEBUG`                  | `True`                         | Django debug mode                    |
| `ALLOWED_HOSTS`          | `localhost,127.0.0.1`          | Hosts the backend will accept        |
| `CORS_ALLOWED_ORIGINS`   | `http://localhost:5173`        | Origins allowed for CORS requests    |
| `FRONTEND_URL`           | `http://localhost:5173`        | Frontend URL used by the backend     |

!!! warning "Production"
    Never use the default `SECRET_KEY` or `POSTGRES_PASSWORD` in production. See [Configuration](configuration.md) for production setup.

## Stopping and Resetting

### Stop the application

```bash
docker compose down
```

### Reset the database

To start fresh and wipe all data:

```bash
docker compose down -v
docker compose up --build
```

The `-v` flag removes the PostgreSQL data volume. On the next start, the database is recreated and re-seeded.

Use this reset after pulling changes that alter migrations or seed data, or when local demo data no longer matches the current branch. A normal `docker compose down` stops containers but keeps the database volume, so old schema/data can survive rebuilds.

## Troubleshooting

### Port conflicts

If port 5173, 8000, or 5432 is already in use, stop the conflicting service or change the port mapping in `docker-compose.yml`.

### Container won't start

Check the logs for a specific container:

```bash
docker compose logs backend
docker compose logs frontend
docker compose logs db
```

### Database connection errors

The backend waits for PostgreSQL to be healthy before starting. If you see connection errors, ensure the `db` container is running:

```bash
docker compose ps
```

If the database container is unhealthy, try resetting it with `docker compose down -v` and restarting.
