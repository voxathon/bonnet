"""Self-signed TLS certificate generation for first-run setup.

Shells out to the system `openssl` binary, the same tool the operator
guide already tells users to run by hand. This just automates that one
command; it does not add a new hard dependency (openssl is not required
unless `--self-signed` is requested, mirroring how ripgrep is optional
for search).
"""

import os
import shutil
import subprocess


class OpenSSLNotFoundError(RuntimeError):
    pass


def generate_self_signed_cert(
    cert_path: str, key_path: str, common_name: str = "localhost", days: int = 365
) -> None:
    """Generate a self-signed RSA-4096 certificate and key with `openssl`.

    Raises OpenSSLNotFoundError if `openssl` is not on PATH, and
    subprocess.CalledProcessError if the command itself fails.
    """
    openssl = shutil.which("openssl")
    if not openssl:
        raise OpenSSLNotFoundError(
            "openssl not found on PATH. Install it, or generate a certificate "
            "manually (see README.md 'Quick Start')."
        )

    for target in (cert_path, key_path):
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)

    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:4096",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            str(days),
            "-nodes",
            "-subj",
            f"/CN={common_name}",
        ],
        check=True,
        capture_output=True,
    )
