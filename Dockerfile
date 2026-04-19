FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download db-ip country database (free, no registration, better coverage than geoip2fast)
RUN apt-get update -qq && apt-get install -y -qq wget && \
    wget -q "https://download.db-ip.com/free/dbip-country-lite-2026-04.mmdb.gz" -O /app/dbip-country.mmdb.gz && \
    gunzip /app/dbip-country.mmdb.gz && \
    apt-get remove -y wget && apt-get autoremove -y -qq && rm -rf /var/lib/apt/lists/*

COPY . .

ENV PORT=8080
EXPOSE 8080

CMD exec gunicorn --bind :$PORT --workers 2 --threads 4 --timeout 120 main:app
