# Minimal Docker image for behavior monitoring with cross-type support
FROM python:3.11-slim

# Install strace, curl, iproute2, Node.js, Wine, and support for mounting DMGs
RUN apt-get update && apt-get install -y \
    strace curl iproute2 nodejs npm wine64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox

CMD ["/bin/bash"]