FROM python:3.11-slim

# Install core analysis tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace curl iproute2 nodejs npm p7zip-full cabextract \
    && rm -rf /var/lib/apt/lists/*

# wine64 is x86_64-only — install if available (ARM64 hosts skip silently)
RUN apt-get update && apt-get install -y --no-install-recommends wine64 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox

CMD ["/bin/bash"]