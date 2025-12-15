FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cloud_drive.py .
COPY templates/ templates/
COPY static/ static/
COPY .well-known/ .well-known/

RUN useradd -m -u 1000 appuser && \
    mkdir -p /data/encrypted /data/temp && \
    chown -R appuser:appuser /app /data

USER appuser

ENV FLASK_APP=cloud_drive.py
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["python", "cloud_drive.py"]

