FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

RUN mkdir -p /app/data && chmod +x /app/scripts/render-start.sh

ENV PYTHONUNBUFFERED=1
ENV SENTINEL_MODE=dev

EXPOSE 5050 10000

CMD ["/app/scripts/render-start.sh"]
