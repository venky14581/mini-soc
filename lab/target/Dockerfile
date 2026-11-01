FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn python-multipart

# Configure simulated SSH server
RUN mkdir /var/run/sshd && \
    echo 'root:toor' | chpasswd && \
    useradd -m -s /bin/bash labuser && \
    echo 'labuser:password123' | chpasswd

COPY app.py .

EXPOSE 8080 22

CMD ["sh", "-c", "/usr/sbin/sshd -D & uvicorn app:app --host 0.0.0.0 --port 8080"]
