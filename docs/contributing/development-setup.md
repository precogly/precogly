# Development Setup

Use this guide when you want to contribute code or documentation to Precogly. The **recommended local workflow is Docker Compose** because it starts the three core services most contributors need—the React frontend, the Django API, and PostgreSQL—plus a development-only AI model forwarder. You can still run frontend commands such as `npm run dev` directly from `frontend/`, but Docker Compose is the fastest way to get a complete working application with seeded demo data.

The development stack mounts the backend source, the frontend `src/` directory, and the shared `libraries/` directory into the containers. That means most frontend and backend code edits are picked up without rebuilding the whole stack. Rebuild when you change dependencies, Dockerfiles, or other files copied into the images during build.

## Local Architecture

```text
Browser
  |
  | http://localhost:5173
  v
precogly-frontend
  React + Vite dev server
  |
  | /api and /media requests
  v
precogly-backend
  Django + Django REST Framework
  |
  | postgres://db:5432/precogly
  v
precogly-postgres
  PostgreSQL 16
```

The frontend talks to the backend through Vite's development proxy. The browser sends API requests to `/api`, and Vite forwards them to the backend container using the `API_URL` value from `docker-compose.yml`.

The `precogly-lmstudio-proxy` container shares the backend network and forwards `localhost:1234` to an OpenAI-compatible model server on the host. It has no host port of its own and is only part of the development stack.

## Prerequisites

Install:

| Tool | Used for |
| --- | --- |
| Docker and Docker Compose | Running the application stack |
| Git | Cloning the repository and preparing pull requests |
| Node.js 22+ | Optional direct frontend workflow |
| [uv](https://docs.astral.sh/uv/getting-started/installation/) | Optional direct backend workflow, and the docs build. Installs its own Python, so a system 3.12 is not needed |

## Start the Stack

From the **repository root**:

```bash
docker compose up --build
```

The first run builds the images, creates the PostgreSQL volume, runs migrations, and seeds demo data. After the services start, open [http://localhost:5173](http://localhost:5173) and log in with:

| Field | Value |
| --- | --- |
| Email | `admin@precogly.dev` |
| Password | `admin123` |

The backend API is available at [http://localhost:8000](http://localhost:8000), and the Django admin is available at [http://localhost:8000/admin](http://localhost:8000/admin) with the same demo credentials.

### The other two demo accounts

The seed creates three accounts across two organizations, all sharing the password
`admin123`. `docker compose up` prints them as a table when seeding finishes.

| Email | Organization | Role |
| --- | --- | --- |
| `admin@precogly.dev` | Demo Organization | Security Team (superuser) |
| `analyst@precogly.dev` | Demo Organization | Member |
| `contoso@precogly.dev` | Contoso Financial | Security Team |

`admin@precogly.dev` is the account to use for working through the product. The other two
exist so that permission and multi-tenancy behaviour is reproducible on a fresh clone.

With one organization whose one user is on the security team, every queryset is scoped to
the organization that user belongs to, so a missing scope and a correct scope return
identical rows — and a role check is indistinguishable from no role check at all. Neither
class of bug can be reproduced, or regression-tested, on a database shaped like that.

`analyst@precogly.dev` is a member of the demo organization and not on its security team,
which is what makes read-versus-write permission differences observable.
`contoso@precogly.dev` belongs to Contoso Financial and to no other organization, so a
listing that leaks across organizations shows up as extra rows rather than as nothing at
all.

## Verify the Stack

Use `docker compose ps` to confirm that all four services are running:

```bash
docker compose ps
```

You should see:

| Service | Expected status |
| --- | --- |
| `precogly-frontend` | Running on port `5173` |
| `precogly-backend` | Running on port `8000` |
| `precogly-postgres` | Healthy on port `5432` |
| `precogly-lmstudio-proxy` | Running (no host port) |

## Daily Development Commands

Run these from the **repository root** unless noted otherwise:

```bash
docker compose ps
docker compose logs backend
docker compose logs frontend
docker compose down
```

Use `docker compose down -v` only when you want to delete the local database volume and reseed from scratch on the next startup.

## Reset Seeded Data

Docker keeps PostgreSQL data in a named volume. That volume survives container rebuilds, so an older local database can drift from the current migrations or seed data after switching branches, pulling new changes, or testing schema-related fixes. When that happens, the app may fail during startup, seed commands may report unexpected constraint errors, or the UI may show stale demo data that does not match the current code.

To reset the local database and reseed from the current branch:

```bash
docker compose down -v
docker compose up --build
```

The `-v` flag deletes the PostgreSQL volume. Use it only for local development data you are comfortable losing.

## Frontend Workflow

The frontend container runs Vite on port `5173`. API calls use `/api` in the browser and are proxied by Vite to the backend container through the `API_URL` value in `docker-compose.yml`.

For direct local frontend work, install dependencies and start Vite from `frontend/`:

```bash
npm install
npm run dev
```

Before opening a frontend pull request, run:

```bash
npm run build
npm run lint
```

Browser tests run with Playwright against the compose stack. The `chromium` project drives the guest editor and needs only the frontend; the `signed-in` project logs in with the seeded demo account (`frontend/e2e/global-setup.ts` fetches a token pair from the API and stores it as Playwright storage state), so the backend must be up and seeded. Specs live beside their feature under `__tests__/e2e/`; a signed-in spec is named `*.signed-in.spec.ts`.

```bash
docker compose up -d
cd frontend
npx playwright install chromium   # first run only
npx playwright test               # both projects
npx playwright test --project=signed-in
```

Set `E2E_API_URL`, `E2E_EMAIL` and `E2E_PASSWORD` to point the signed-in project at another backend or account. CI runs the same command in the `e2e` job.

Frontend changes should include screenshots or a short screen recording in the pull request description.

## Backend Workflow

The backend container runs migrations, seeds demo data, and starts Django on port `8000`. To run backend commands inside the same environment as the app:

```bash
docker compose exec backend python manage.py migrate
docker compose exec backend python manage.py seed
docker compose exec backend python -m pytest
```

For direct local backend work, install [uv](https://docs.astral.sh/uv/getting-started/installation/) and run commands from `backend/`:

```bash
cd backend
uv sync                                # creates .venv from uv.lock
uv run python manage.py migrate
uv run python -m pytest
```

`uv sync` installs the base and `dev` dependency groups; add `--group prod` for the deployment runtime (gunicorn, celery, sentry). `uv run` picks up `DJANGO_SETTINGS_MODULE` from `pyproject.toml`'s pytest settings for tests, and `manage.py` defaults to the development module otherwise.

To add or remove a dependency, use `uv add` / `uv remove` rather than editing `pyproject.toml` by hand.

## Documentation Workflow

Preview documentation changes locally:

```bash
uvx --from 'mkdocs-material>=9.5,<10.0' mkdocs serve
```

Before opening a documentation pull request, run the strict build to catch broken links, invalid navigation, and Markdown configuration errors:

```bash
uvx --from 'mkdocs-material>=9.5,<10.0' mkdocs build --strict
```

## Troubleshooting

If the frontend loads but API requests fail, check that the backend is healthy with `docker compose ps` and inspect logs with `docker compose logs backend`. If the database is in a bad local state, stop the stack with `docker compose down -v` and start again with `docker compose up --build`.

If ports `5173`, `8000`, or `5432` are already in use, stop the conflicting process or change the port mapping in `docker-compose.yml`. Keep any changed local port mappings out of the pull request unless the project intentionally needs them.

For a local PostgreSQL conflict, change only the host side of the database port mapping in `docker-compose.yml`, for example from `"5432:5432"` to `"5433:5432"`, then keep that local change out of your pull request:

```bash
docker compose up --build
```
