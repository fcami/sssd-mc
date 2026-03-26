#!/usr/bin/env python3
# SPDX-FileCopyrightText: ensure-builder-image.py 2026, ["François Cami" <contribs@fcami.net>]
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Ensure a UBI builder container image exists and is fresh (<90 days).

Usage: ensure-builder-image.py <rhel-version>
  where <rhel-version> is 8, 9, or 10.
"""

import subprocess
import sys
from datetime import date, datetime

PROJECT = "sssd-mc-builder"
MAX_AGE_DAYS = 90

CONTAINERFILE_TEMPLATE = """\
FROM registry.access.redhat.com/ubi{ver}/ubi:latest
RUN dnf install -y rust cargo gcc make && dnf clean all
"""


def image_name(ver: str) -> str:
    return f"{PROJECT}-rhel{ver}"


def get_latest_tag(name: str) -> str | None:
    """Find the newest <name>:YYYYMMDD tag."""
    result = subprocess.run(
        ["podman", "images", "--format", "{{.Repository}}:{{.Tag}}"],
        capture_output=True, text=True, check=True,
    )
    tags = sorted(
        (
            line.split(":")[-1]
            for line in result.stdout.splitlines()
            if line.startswith(f"localhost/{name}:")
        ),
        reverse=True,
    )
    return tags[0] if tags else None


def tag_age_days(tag: str) -> int:
    """Return the age in days of a YYYYMMDD tag."""
    created = datetime.strptime(tag, "%Y%m%d").date()
    return (date.today() - created).days


def build_image(name: str, ver: str, tag: str) -> None:
    """Build the builder image with the given tag."""
    full_tag = f"{name}:{tag}"
    containerfile = CONTAINERFILE_TEMPLATE.format(ver=ver)
    subprocess.run(
        ["podman", "build", "-t", full_tag, "-f", "-", "."],
        input=containerfile, text=True, check=True,
    )
    print(f"[builder] Created {full_tag}")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("8", "9", "10"):
        print(f"Usage: {sys.argv[0]} <8|9|10>", file=sys.stderr)
        sys.exit(1)

    ver = sys.argv[1]
    name = image_name(ver)
    latest = get_latest_tag(name)

    if latest is not None:
        age = tag_age_days(latest)
        if age < MAX_AGE_DAYS:
            print(f"[builder] Using existing image: {name}:{latest} ({age}d old)")
            return
        print(f"[builder] Image {name}:{latest} is {age}d old (>{MAX_AGE_DAYS}d), rebuilding...")
    else:
        print(f"[builder] No {name} image found, creating...")

    build_image(name, ver, date.today().strftime("%Y%m%d"))


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"[builder] Command failed: {e}", file=sys.stderr)
        sys.exit(1)
