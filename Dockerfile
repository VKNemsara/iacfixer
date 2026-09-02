FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends bash curl git passwd util-linux && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && ansible-galaxy collection install -p /usr/share/ansible/collections community.docker

RUN useradd --create-home --shell /bin/bash appuser
USER appuser
ENV HOME=/home/appuser PATH=/home/appuser/.local/bin:$PATH
# OAuth credentials are stored under HOME and persisted by the compose volume.
RUN curl -fsSL https://antigravity.google/cli/install.sh | bash

COPY --chown=appuser:appuser app ./app
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod 755 /usr/local/bin/docker-entrypoint
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
