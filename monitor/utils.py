
import re
from typing import List, Set, FrozenSet, Tuple

# --- Shared Constants ---

BENIGN_BINARIES: FrozenSet[str] = frozenset([
    "/usr/local/bin/pip", "/usr/bin/pip",
    "/usr/local/bin/python", "/usr/bin/python",
    "/usr/local/bin/python3", "/usr/bin/python3",
    "/usr/bin/sh", "/usr/local/bin/sh",
    "/bin/sh", "/bin/bash",
    "/usr/local/bin/npm", "/usr/bin/npm",
    "/usr/local/bin/node", "/usr/bin/node",
    "/usr/bin/ip", "/sbin/ip",
    # pip calls these for platform fingerprinting (wheel tag selection)
    "/usr/bin/uname", "/bin/uname", "/usr/local/bin/uname",
    "/usr/sbin/uname", "/usr/local/sbin/uname", "/sbin/uname",
    "/usr/bin/lsb_release", "/bin/lsb_release", "/usr/local/bin/lsb_release",
    "/usr/sbin/lsb_release", "/usr/local/sbin/lsb_release", "/sbin/lsb_release",
])

KNOWN_SAFE_NETWORKS: FrozenSet[str] = frozenset([
    "151.101.",        # PyPI CDN (Fastly)
    "104.16.",         # PyPI (Cloudflare)
    "104.17.",
    "151.101.0.",
    "151.101.64.",
    "151.101.128.",
    "151.101.192.",
    "52.85.",          # npm CDN
    "54.230.",
    "13.107.",         # GitHub / Azure
    "52.96.",
    "40.79.",
    "140.82.121.",     # github.com
    "140.82.112.",
    "185.199.108.",    # raw.githubusercontent.com
    "185.199.109.",
    "185.199.110.",
    "185.199.111.",
    "199.232.",        # npm registry (jsDelivr / CloudFront)
    "99.84.",
    "99.86.",
    "13.224.",         # CloudFront
    "13.225.",
    "13.226.",
    "13.227.",
    "3.160.",
    "3.162.",
    "3.164.",
    "3.165.",
    "3.166.",
    "3.167.",
    "3.168.",
    "205.251.",        # AWS CloudFront
    "13.249.",
])

# --- Sensitive File Detection ---

# Literal substrings that are sensitive.
# Case-sensitive matching is significantly faster in Python's regex engine.
_SENSITIVE_LITERALS = (
    "/etc/passwd",
    "/etc/shadow",
    ".ssh/",
    ".aws/",
    ".kube/config",
    ".env",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".netrc",
    "/proc/self/environ",
    "/proc/net/",
    "/crontab",
    ".bash_history",
    "/etc/cron",
    "/var/run/secrets",
    "discordcanary",
    "Google/Chrome",
    "Local Storage/leveldb",
)

# Regex patterns for more complex matching.
_SENSITIVE_REGEX_PATTERNS = (
    r"/proc/\d+/",
    r"^/tmp/\.[^/]+",
)

# Pre-compiled case-sensitive regex for literals (fast path)
_SENSITIVE_LITERAL_REGEX = re.compile("|".join(map(re.escape, _SENSITIVE_LITERALS)))
# Pre-compiled regex for complex patterns
_SENSITIVE_COMPLEX_REGEX = re.compile("|".join(_SENSITIVE_REGEX_PATTERNS))

# Specific "secrets" subset (for signatures.py)
_SECRET_LITERALS = (".env", ".npmrc", ".aws/credentials", ".ssh/id_rsa")
_SECRET_REGEX = re.compile("|".join(map(re.escape, _SECRET_LITERALS)))

def is_sensitive_path(path: str) -> bool:
    """
    Checks if a path is sensitive using pre-compiled regexes for efficiency.
    Returns True if any sensitive pattern matches the path.
    """
    if not path:
        return False
    # Check fast literal regex first
    if _SENSITIVE_LITERAL_REGEX.search(path):
        return True
    # Check complex patterns
    return bool(_SENSITIVE_COMPLEX_REGEX.search(path))

def is_secret_path(path: str) -> bool:
    """
    Checks if a path matches a specific 'secret' pattern (subset of sensitive).
    """
    if not path:
        return False
    return bool(_SECRET_REGEX.search(path))
