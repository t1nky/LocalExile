"""The current Path of Exile client version, from GGG's patch server (standard library only; used by CI).

    python -I scripts/ci/patch_version.py                         # version=3.29.3.3, web_root=..., exe_url=...
    python -I scripts/ci/patch_version.py --github-output "$GITHUB_OUTPUT"

The patch server (patch.pathofexile.com:12995) answers the request `01 07` with: id 0x02, a 32-byte hash, then the
CDN web root as a u16 big-endian character count + UTF-16LE text (a second root follows the same way). The web root
is versioned, e.g. https://patch.poecdn.com/3.29.3.3/, and holds that version's PathOfExile.exe. Only the current
version stays on the CDN. Fails (exit 1) on anything unexpected rather than guessing.
"""
import argparse
import re
import socket
import struct
import sys
from urllib.parse import urlparse

HOST, PORT = "patch.pathofexile.com", 12995
VERSION = re.compile(r"[0-9]+(\.[0-9]+){2,3}")


def read_reply(sock):
    """The reply bytes: id, hash, and two length-prefixed UTF-16LE strings."""
    data = b""
    while True:
        chunk = sock.recv(4096)
        if chunk:
            data += chunk
        if len(data) >= 35:
            first = 35 + 2 * struct.unpack_from(">H", data, 33)[0]
            if len(data) >= first + 2 and len(data) >= first + 2 + 2 * struct.unpack_from(">H", data, first)[0]:
                return data
        if not chunk:
            raise ValueError(f"patch server closed the connection after {len(data)} bytes")


def parse_reply(data):
    """(web root, hash hex) from a patch-server reply."""
    if len(data) < 35 or data[0] != 0x02:
        raise ValueError(f"unexpected patch server reply: {data[:8].hex()}")
    count = struct.unpack_from(">H", data, 33)[0]
    return data[35:35 + 2 * count].decode("utf-16-le"), data[1:33].hex()


def version_of(web_root):
    """The version in a versioned CDN web root; refuses anything but an https poecdn.com root."""
    url = urlparse(web_root)
    parts = [p for p in url.path.split("/") if p]
    if url.scheme != "https" or not (url.hostname or "").endswith(".poecdn.com") or len(parts) != 1 \
            or not VERSION.fullmatch(parts[0]) or not web_root.endswith("/"):
        raise ValueError(f"unexpected web root: {web_root!r}")
    return parts[0]


def current(host=HOST, port=PORT, timeout=15):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(bytes([0x01, 0x07]))
        web_root, _ = parse_reply(read_reply(sock))
    return {"version": version_of(web_root), "web_root": web_root, "exe_url": web_root + "PathOfExile.exe"}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--github-output", help="also append key=value lines to this file")
    options = parser.parse_args()
    try:
        result = current()
    except (OSError, ValueError) as error:
        print(f"patch_version: {error}", file=sys.stderr)
        return 1
    lines = [f"{key}={value}" for key, value in result.items()]
    print("\n".join(lines))
    if options.github_output:
        with open(options.github_output, "a", encoding="utf-8") as output:
            output.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
