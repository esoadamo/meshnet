FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN uv sync --no-dev --frozen --no-cache

ENTRYPOINT ["uv", "run", "meshnet"]
