FROM python:3.14-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /uvx /usr/local/bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON_PREFERENCE=only-system

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Una revisión fija evita que un cambio en master altere el próximo build.
ARG THEHARVESTER_REF=6790b147f52309e4eee22ed941db1d285ab2ec23
RUN git clone https://github.com/laramies/theHarvester.git /opt/theHarvester \
    && git -C /opt/theHarvester checkout --detach "$THEHARVESTER_REF"

WORKDIR /opt/theHarvester
RUN uv sync --frozen --no-dev \
    && .venv/bin/theHarvester -h >/dev/null

WORKDIR /app
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/app ./app
RUN pip install --no-cache-dir . \
    && useradd --create-home --system baxtersec

USER baxtersec
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
