FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

# Install core analysis tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace curl iproute2 nodejs npm p7zip-full cabextract \
    && rm -rf /var/lib/apt/lists/*

# wine64 is x86_64-only — install if available (ARM64 hosts skip silently)
RUN apt-get update && apt-get install -y --no-install-recommends wine64 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox

CMD ["/bin/bash"]