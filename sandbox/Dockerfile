# Minimal Docker image for behavior monitoring
FROM python:3.11-slim

# Install strace, curl, and iproute2 (for ip commands)
RUN apt-get update && apt-get install -y strace curl iproute2 && rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox

CMD ["/bin/bash"]
