# One image for every zone; each service runs as its own non-root user.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH PYTHONPATH=/app PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
COPY tools ./tools
COPY lab ./lab
RUN uv sync --locked --no-dev

# Distinct UIDs per zone. Named volumes inherit these owners on first use.
RUN useradd -u 10001 -M gateway && useradd -u 10002 -M tools && useradd -u 10003 -m agent \
 && mkdir -p /var/lib/gateway/log /var/lib/gateway/anchor /var/lib/tools \
 && chown -R gateway /var/lib/gateway && chown -R tools /var/lib/tools \
 && chmod 700 /var/lib/gateway/log /var/lib/gateway/anchor /var/lib/tools
