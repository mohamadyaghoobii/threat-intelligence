"""Exercise the IP export with controlled data in an isolated temporary store."""
import csv
import io
import ipaddress
import shutil
import uuid
from datetime import timedelta
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import suite
from splunk_feed import IP_LOOKUP, install, stage, validated


def observation(kind, value, expires):
    return dict(type=kind, value=value, source="controlled-test", raw=value, expires=expires.isoformat())


def check(root):
    start = suite.date(suite.now())
    short = start + timedelta(hours=1)
    long = start + timedelta(hours=3)
    rows = [
        observation("ipv4", "45.33.32.156", short),
        observation("cidr", "45.33.32.156/32", short),
        observation("ipv4", "45.33.32.156", short),
        observation("cidr", "45.33.32.0/24", long),
        observation("ipv6", "2600:3c01::a", long),
        observation("cidr", "2600:3c01::/48", long),
        observation("ipv4", "10.0.0.7", long),
        observation("cidr", "192.0.2.0/24", long),
        observation("ipv4", "1.1.1.1", long),
        observation("ip:port", "45.33.33.156:443", long),
        observation("ipv4", "45.33.34.156", start - timedelta(seconds=1)),
    ]
    with patch.object(suite, "DATA", root / "db"), patch.dict(suite.CONFIG, allowlist=["1.1.1.1/32"]), patch("sources.collect", return_value=rows):
        with redirect_stdout(io.StringIO()):
            suite.run("ip", "demo")
        try:
            stage(root / "packages", "ip")
        except ValueError as error:
            assert str(error) == "No live ip publication"
        else:
            raise AssertionError("Demo snapshot was accepted for live export")
        # Controlled inputs exercise the live-only contract in this isolated database.
        with redirect_stdout(io.StringIO()):
            suite.run("ip", "live")
        package = stage(root / "packages", "ip")
        manifest, body = validated(package)
        target = root / IP_LOOKUP
        install(package, target, False)
        assert target.read_bytes() == body and manifest["rows"] == 4
        table = list(csv.DictReader(io.StringIO(body.decode())))
        assert [row["network"] for row in table] == [
            "45.33.32.156/32", "45.33.32.0/24", "2600:3c01::a/128", "2600:3c01::/48"
        ]

        def first_match(value, when):
            address = ipaddress.ip_address(value)
            for row in table:
                if address in ipaddress.ip_network(row["network"]):
                    return row["network"] if int(row["expires_epoch"]) > when.timestamp() else "expired_candidate"
            return None

        # Model a file-order lookup with max_matches=1. Confirm on Splunk before rollout.
        assert first_match("45.33.32.156", start) == "45.33.32.156/32"
        assert first_match("2600:3c01::a", start) == "2600:3c01::a/128"
        assert first_match("45.33.32.157", start) == "45.33.32.0/24"
        assert first_match("2600:3c01::b", start) == "2600:3c01::/48"
        assert first_match("45.33.33.156", start) is None
        assert first_match("45.33.32.156", short) == "expired_candidate"
        assert first_match("45.33.32.157", short) == "45.33.32.0/24"
        with patch("suite.now", return_value=long.isoformat()):
            try:
                install(package, target, False)
            except ValueError as error:
                assert "fully expired" in str(error)
            else:
                raise AssertionError("Fully expired package was accepted")
        assert target.read_bytes() == body


if __name__ == "__main__":
    directory = suite.DATA / f"ip-preflight-{uuid.uuid4().hex}"
    directory.mkdir(parents=True)
    try:
        check(directory)
    finally:
        shutil.rmtree(directory)
    print("Controlled IP preflight passed. No controlled artifact retained.")
