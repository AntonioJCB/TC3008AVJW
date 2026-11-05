FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SPIDERFOOT_DATA=/var/lib/spiderfoot \
    SPIDERFOOT_LOGS=/var/lib/spiderfoot/log \
    SPIDERFOOT_CACHE=/var/lib/spiderfoot/cache

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates git build-essential libffi-dev libssl-dev \
       libxml2-dev libxslt1-dev rustc cargo \
    && rm -rf /var/lib/apt/lists/*

# El commit se fija para que todo el equipo construya la misma versión.
ARG SPIDERFOOT_REF=0f815a203afebf05c98b605dba5cf0475a0ee5fd
RUN git clone https://github.com/smicallef/spiderfoot.git /opt/spiderfoot \
    && git -C /opt/spiderfoot checkout --detach "$SPIDERFOOT_REF"

WORKDIR /opt/spiderfoot
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --system spiderfoot \
    && mkdir -p "$SPIDERFOOT_DATA" "$SPIDERFOOT_LOGS" "$SPIDERFOOT_CACHE" \
    && chown -R spiderfoot:spiderfoot "$SPIDERFOOT_DATA"

USER spiderfoot
EXPOSE 5001
CMD ["python", "sf.py", "-l", "0.0.0.0:5001"]
