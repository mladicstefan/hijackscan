# The hijackscan demo image: the web page (built with Node) plus the Python API, in one image.
# Built and started by `docker compose up` (docker-compose.yml); nothing else needs to be installed.

# ---------------------------------------------------------------- stage 1: build the web page
FROM node:24-slim AS web
WORKDIR /web
# The package files first: Docker reuses this layer (and the installed packages) until they change.
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---------------------------------------------------------------- stage 2: the app
FROM python:3.13-slim AS app
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /usr/local/bin/uv

# Use the image's Python (stable 3.13) and never download another; compile .py files at install time.
ENV UV_PYTHON=/usr/local/bin/python3 \
    UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PYTHONUNBUFFERED=1

WORKDIR /app
# Dependencies first (cached until uv.lock changes), then the project itself.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src/ src/
RUN uv sync --frozen --no-dev

# The demo data: the two domain lists and their collected records (no scan needed).
COPY data/samples/dev100.txt data/samples/ee100.txt data/samples/
COPY data/demo/ data/demo/
# The built page from stage 1; the API serves it at "/".
COPY --from=web /web/dist web/dist
COPY docker/entrypoint.sh /entrypoint.sh

# Run as an ordinary user, not root: the app only reads files and talks to MongoDB.
RUN useradd --system --no-create-home hijackscan
USER hijackscan

ENV PATH="/app/.venv/bin:$PATH" \
    HIJACKSCAN_MONGO_URL=mongodb://mongo:27017
EXPOSE 8000
ENTRYPOINT ["sh", "/entrypoint.sh"]
