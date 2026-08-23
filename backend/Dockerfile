# ---- Base ----
FROM python:3.14-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements/ requirements/

# ---- Development ----
FROM base AS dev

RUN pip install --no-cache-dir -r requirements/development.txt

ENV DJANGO_SETTINGS_MODULE=config.settings.development

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py seed && python manage.py runserver 0.0.0.0:8000"]

# ---- Production ----
FROM base AS prod

RUN pip install --no-cache-dir -r requirements/production.txt

ENV DJANGO_SETTINGS_MODULE=config.settings.production

COPY . .

RUN python manage.py collectstatic --noinput 2>/dev/null || true

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 4 --threads 2"]
