# The build context is the repository root, not `backend/`. uv keeps one lock per
# workspace and the workspace root is the repository root, so `uv.lock` and the
# `mcp/` member both sit outside this directory. docker-compose.yml sets
# `context: .` and `dockerfile: backend/Dockerfile` for that reason.

# ---- Base ----
FROM python:3.14-slim AS base

# uv defaults the venv to $PROJECT/.venv, which docker-compose.yml's
# ./backend:/app/backend mount would shadow. uv's Docker guide masks it with an
# anonymous volume; compose carries those across container recreation (-V opts
# out), so a rebuild after a dependency change would silently serve the old venv.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.9.13 /uv /usr/local/bin/uv

# Both members' manifests, because uv reads every member of the workspace before
# it will resolve any of it. Sources stay out of this layer so a code change does
# not invalidate the dependency install below.
COPY pyproject.toml uv.lock ./
COPY backend/pyproject.toml backend/
COPY mcp/pyproject.toml mcp/

# ---- Development ----
FROM base AS dev

# Dependencies only. --no-install-workspace, not --no-install-project: there is no
# root project to skip — the root is virtual — so --no-install-project would go
# ahead and install precogly-mcp from sources this layer does not have.
#
# --frozen fails on a stale uv.lock instead of re-resolving, so an image cannot be
# built from dependencies nobody committed.
RUN uv sync --frozen --no-install-workspace

ENV DJANGO_SETTINGS_MODULE=config.settings.development

COPY backend/ backend/
COPY mcp/ mcp/
# The pack sources settings.LIBRARIES_PATH points at. Copied rather than left to a
# mount, because production runs this image with no volumes and an image that
# cannot seed its libraries comes up with every catalog empty.
COPY libraries/ libraries/

# Now that mcp/ exists, install the member itself. uv installs workspace members
# editable — a .pth pointing at /app/mcp — so the compose mount over that path is
# live, the same way the old container-start `pip install -e` was.
RUN uv sync --frozen

WORKDIR /app/backend

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py seed && python manage.py runserver 0.0.0.0:8000"]

# ---- Production ----
FROM base AS prod

# uv installs `dev` by default; --no-default-groups drops it. The flags repeat on
# the second sync because uv reconciles the environment against them each time,
# and omitting them there would put the dev group back.
RUN uv sync --frozen --no-install-workspace --no-default-groups --group prod

ENV DJANGO_SETTINGS_MODULE=config.settings.production

COPY backend/ backend/
COPY mcp/ mcp/
# The pack sources settings.LIBRARIES_PATH points at. Copied rather than left to a
# mount, because production runs this image with no volumes and an image that
# cannot seed its libraries comes up with every catalog empty.
COPY libraries/ libraries/

RUN uv sync --frozen --no-default-groups --group prod

WORKDIR /app/backend

RUN python manage.py collectstatic --noinput 2>/dev/null || true

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 4 --threads 2"]
