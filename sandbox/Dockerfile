FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# Install core analysis tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace curl iproute2 nodejs npm p7zip-full cabextract \
    && rm -rf /var/lib/apt/lists/*

# wine64 is x86_64-only — install if available (ARM64 hosts skip silently)
RUN apt-get update && apt-get install -y --no-install-recommends wine64 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox

CMD ["/bin/bash"]