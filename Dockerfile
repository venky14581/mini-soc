FROM python:3.12-slim

# Install system dependencies including iptables for SOAR automated containment
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    curl \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

EXPOSE 8000 8001

CMD ["uvicorn", "siem.api:app", "--host", "0.0.0.0", "--port", "8000"]
