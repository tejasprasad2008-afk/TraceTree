FROM python:3.11-slim

# Install strace, curl, iproute2, Node.js, Wine, and binary analysis tools
# p7zip-full handles DMG, EXE, MSI, CAB extraction; wine64 runs Windows executables
RUN apt-get update && apt-get install -y \
    strace curl iproute2 nodejs npm wine64 p7zip-full cabextract \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox

CMD ["/bin/bash"]