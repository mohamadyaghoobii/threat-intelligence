"""Stage live Central and IP publications and install verified Splunk lookup files."""
import argparse
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
from contextlib import closing
from pathlib import Path
from tempfile import NamedTemporaryFile

import suite

SCHEMA = "ojan-splunk-hash-v1"
COLUMNS = ("indicator_type", "indicator_value", "source", "provider_confidence",
           "provider_observed_at", "ingested_at", "expires", "expires_epoch",
           "publication_id", "published_epoch", "fresh_until_epoch", "mode")
HASH_LENGTH = {"md5": 32, "sha1": 40, "sha256": 64}
LOOKUP = "ojan_live_hashes.csv"
IP_SCHEMA = "ojan-splunk-cidr-v1"
IP_LOOKUP = "ojan_live_networks.csv"
IP_COLUMNS = ("network",) + COLUMNS


def contract(feed):
    if feed == "central":
        return SCHEMA, LOOKUP, COLUMNS
    if feed == "ip":
        return IP_SCHEMA, IP_LOOKUP, IP_COLUMNS
    raise ValueError("Unsupported Splunk feed")


def indicator_network(kind, value):
    if kind == "cidr":
        net = ipaddress.ip_network(value, strict=True)
        if str(net) != value:
            raise ValueError("Expected a canonical CIDR")
    elif kind in ("ipv4", "ipv6"):
        address = ipaddress.ip_address(value)
        if kind != f"ipv{address.version}" or str(address) != value:
            raise ValueError("Expected a canonical IP address")
        net = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
    else:
        raise ValueError("Expected an IP address or network")
    if (not net.network_address.is_global or not net.broadcast_address.is_global
            or any(net.overlaps(n) for n in suite.SPECIAL if n.version == net.version)):
        raise ValueError("Reserved network in lookup")
    return net


def epoch(value):
    return int(suite.date(value).timestamp())


def digest(body):
    return hashlib.sha256(body).hexdigest()


def atomic_write(path, body):
    with NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        stream.write(body)
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def validated(package):
    manifest = suite.read(package / "manifest.json")
    pub = manifest["publication_id"]
    feed = manifest["feed"]
    schema, filename, columns = contract(feed)
    if (manifest["schema"], manifest["mode"]) != (schema, "live") or not re.fullmatch("[0-9a-f]{32}", pub):
        raise ValueError("Expected a versioned live Splunk package")
    body = (package / filename).read_bytes()
    if digest(body) != manifest["sha256"]:
        raise ValueError("Lookup checksum mismatch")
    reader = csv.DictReader(io.StringIO(body.decode("utf-8")))
    if tuple(reader.fieldnames or []) != columns:
        raise ValueError("Unexpected lookup headers")
    seen = set()
    for row in reader:
        value = row["indicator_value"]
        length = HASH_LENGTH.get(row["indicator_type"], 0)
        if None in row or None in row.values():
            raise ValueError("Invalid lookup row width")
        key = value
        if feed == "ip":
            key = str(indicator_network(row["indicator_type"], value))
            if row["network"] != key:
                raise ValueError("Network does not match indicator value")
        elif not length or not re.fullmatch(f"[0-9a-f]{{{length}}}", value):
            raise ValueError("Invalid hash value")
        if (key in seen or row["mode"] != "live" or row["publication_id"] != pub or not row["source"]
                or int(row["expires_epoch"]) != epoch(row["expires"])
                or int(row["published_epoch"]) != epoch(manifest["published"])
                or int(row["fresh_until_epoch"]) != epoch(manifest["fresh_until"])):
            raise ValueError("Invalid or duplicate lookup row")
        suite.date(row["ingested_at"])
        if row["provider_observed_at"]:
            suite.date(row["provider_observed_at"])
        seen.add(key)
    if not seen or len(seen) != manifest["rows"]:
        raise ValueError("Lookup row count mismatch")
    return manifest, body


def stage(root, feed="central"):
    schema, filename, columns = contract(feed)
    with closing(suite.db()) as conn:
        publication = suite.latest(conn, "publications", "live", feed)
    if not publication:
        raise ValueError(f"No live {feed} publication")
    pub = publication["version"]
    source = suite.folder("live", feed, pub)
    original = suite.read(source / "manifest.json")
    data = (source / "lookup.json").read_bytes()
    if (original["mode"], original["feed"], original["version"]) != ("live", feed, pub) or digest(data) != original["sha256"]["lookup.json"]:
        raise ValueError("Source publication identity or checksum mismatch")
    records = json.loads(data)
    if len(records) != original["outputs"]:
        raise ValueError("Source publication row count mismatch")
    rows = []
    networks = {}
    for record in records:
        observations = record["observations"]
        if record["status"] != "active" or not observations:
            raise ValueError("Expected an active record with source evidence")
        sources = sorted({o["source"] for o in observations})
        confidence = {str(o["confidence"]) for o in observations if o.get("confidence") is not None}
        provider_dates = [o["provider_time"] for o in observations if o.get("provider_time") and not o.get("publisher_metadata")]
        row = dict(indicator_type=record["type"], indicator_value=record["value"],
                         source="|".join(sources),
                         provider_confidence=next(iter(confidence)) if len(sources) == len(confidence) == 1 and all(o.get("confidence") is not None for o in observations) else "",
                         provider_observed_at=max(provider_dates, key=suite.date, default=""),
                         ingested_at=max((o["ingested"] for o in observations), key=suite.date),
                         expires=record["expires"], expires_epoch=epoch(record["expires"]),
                         publication_id=pub, published_epoch=epoch(original["published"]),
                         fresh_until_epoch=epoch(original["expires"]), mode="live")
        if feed == "ip":
            if record["type"] == "ip:port":
                continue
            network = indicator_network(record["type"], record["value"])
            row["network"] = str(network)
            prior = networks.get(network)
            # A bare address and its host CIDR represent the same match.
            # Keep the most recently expiring evidence rather than duplicating hits.
            if prior is None or (row["expires_epoch"], row["indicator_type"], row["indicator_value"]) > (
                    prior["expires_epoch"], prior["indicator_type"], prior["indicator_value"]):
                networks[network] = row
        else:
            rows.append(row)
    if feed == "ip":
        rows = [networks[n] for n in sorted(networks, key=lambda n: (n.version, -n.prefixlen, int(n.network_address)))]
    if not rows:
        raise ValueError("No eligible rows for the Splunk lookup")
    body = suite.csvbytes(columns, rows)
    package = root / pub
    package.mkdir(parents=True, exist_ok=True)
    manifest = dict(schema=schema, mode="live", feed=feed, publication_id=pub,
                    published=original["published"], fresh_until=original["expires"],
                    rows=len(rows), sha256=digest(body), upstream_lookup_sha256=digest(data))
    atomic_write(package / filename, body)
    atomic_write(package / "manifest.json", json.dumps(manifest, indent=2).encode())
    validated(package)
    return package


def install(package, destination, rollback):
    manifest, body = validated(package)
    known_destinations = {LOOKUP: "central", IP_LOOKUP: "ip"}
    expected = known_destinations.get(destination.name.lower())
    if expected is not None and manifest["feed"] != expected:
        raise ValueError("Package feed does not match destination")
    now = epoch(suite.now())
    if not rollback and (epoch(manifest["fresh_until"]) <= now or not any(
            int(row["expires_epoch"]) > now for row in csv.DictReader(io.StringIO(body.decode())))):
        raise ValueError("Refusing a stale or fully expired publication")
    atomic_write(destination, body)
    return manifest["publication_id"]


def write_health(destination):
    rows = []
    for feed, info in suite.state("live").items():
        manifest, attempt = info["manifest"], info["attempt"]
        rows.append(dict(feed=feed, publication_id=manifest.get("version"), mode="live",
                         published_epoch=epoch(manifest["published"]) if manifest else "",
                         fresh_until_epoch=epoch(manifest["expires"]) if manifest else "",
                         last_attempt=attempt.get("started"), last_successful_parse=info["parsed"],
                         stage=attempt.get("stage"), source_error=attempt.get("error"),
                         exported_epoch=epoch(suite.now())))
    atomic_write(destination,suite.csvbytes(tuple(rows[0]),rows))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    build = commands.add_parser("stage")
    build.add_argument("root", type=Path)
    build.add_argument("--feed", choices=("central", "ip"), default="central")
    commands.add_parser("verify").add_argument("package", type=Path)
    commands.add_parser("health").add_argument("destination", type=Path)
    apply = commands.add_parser("install")
    apply.add_argument("package", type=Path)
    apply.add_argument("destination", type=Path)
    apply.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "stage":
            print(stage(args.root, args.feed))
        elif args.action == "verify":
            print(json.dumps(validated(args.package)[0], indent=2))
        elif args.action == "health":
            write_health(args.destination)
            print(args.destination)
        else:
            print(install(args.package,args.destination,args.rollback))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"{exc}\n")
