"""Command-line interface."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

from netwatch import __version__
from netwatch.alerts import build_message, send_webhook
from netwatch.discovery import DiscoveryError, arp_sweep, require_root, resolve_hostnames, validate_network
from netwatch.inventory import Inventory
from netwatch.models import Device, ScanDiff
from netwatch.ports import parse_ports, scan_hosts
from netwatch.report import render_csv, render_json, render_summary, render_table

log = logging.getLogger("netwatch")

DEFAULT_DB = "netwatch.json"
EXIT_UNKNOWN_DEVICE = 3


def _scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("network", help="IPv4 network in CIDR form, e.g. 192.168.1.0/24")
    parser.add_argument("-i", "--iface", help="network interface (default: chosen by the routing table)")
    parser.add_argument(
        "-p",
        "--ports",
        default="common",
        help='ports to check: "common" (default), "none", or a list like "22,80,8000-8100"',
    )
    parser.add_argument("--arp-timeout", type=float, default=2.0, help="seconds to wait for ARP replies (default: 2)")
    parser.add_argument("--port-timeout", type=float, default=0.5, help="TCP connect timeout in seconds (default: 0.5)")
    parser.add_argument("--workers", type=int, default=200, help="concurrent port checks (default: 200)")
    parser.add_argument("--no-dns", action="store_true", help="skip reverse DNS lookups")
    parser.add_argument(
        "--webhook",
        default=os.environ.get("NETWATCH_WEBHOOK"),
        help="Slack/Google Chat/Mattermost webhook for alerts (or set NETWATCH_WEBHOOK)",
    )
    parser.add_argument(
        "--trust-new",
        action="store_true",
        help="mark every new device as trusted (use on the first run to build a baseline)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netwatch",
        description="Discover devices on your network and alert when an unknown one appears.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--db",
        type=Path,
        default=Path(os.environ.get("NETWATCH_DB", DEFAULT_DB)),
        help=f"inventory file (default: ./{DEFAULT_DB} or $NETWATCH_DB)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan once, update the inventory and report changes")
    _scan_options(scan)
    scan.add_argument("-f", "--format", choices=("table", "json", "csv"), default="table")
    scan.add_argument("-o", "--output", type=Path, help="also write results to this file")
    scan.add_argument(
        "--fail-on-unknown",
        action="store_true",
        help=f"exit with code {EXIT_UNKNOWN_DEVICE} if an unknown device is found (for cron/CI)",
    )

    watch = sub.add_parser("watch", help="scan repeatedly and alert on unknown devices")
    _scan_options(watch)
    watch.add_argument("--interval", type=int, default=300, help="seconds between scans (default: 300)")

    devices = sub.add_parser("devices", help="list devices in the inventory")
    devices.add_argument("-f", "--format", choices=("table", "json", "csv"), default="table")
    devices.add_argument("--unknown", action="store_true", help="show only untrusted devices")

    trust = sub.add_parser("trust", help="mark a device as trusted")
    trust.add_argument("mac")
    trust.add_argument("-l", "--label", help='friendly name, e.g. "Office printer"')

    untrust = sub.add_parser("untrust", help="mark a device as untrusted")
    untrust.add_argument("mac")

    forget = sub.add_parser("forget", help="remove a device from the inventory")
    forget.add_argument("mac")
    return parser


def run_scan(args: argparse.Namespace, inventory: Inventory) -> tuple[list[Device], ScanDiff]:
    network = validate_network(args.network)
    ports = parse_ports(args.ports)
    require_root()

    started = time.monotonic()
    devices = arp_sweep(network, iface=args.iface, timeout=args.arp_timeout)
    if devices and ports:
        open_ports = scan_hosts([d.ip for d in devices], ports, timeout=args.port_timeout, workers=args.workers)
        for device in devices:
            device.open_ports = open_ports[device.ip]
    if devices and not args.no_dns:
        resolve_hostnames(devices)

    diff = inventory.update(devices, ports_scanned=bool(ports), trust_new=args.trust_new)
    inventory.save()
    log.debug("scan of %s took %.1fs", network, time.monotonic() - started)

    message = build_message(diff, str(network))
    if message:
        log.warning(message)
        if args.webhook and not send_webhook(args.webhook, message):
            log.error("could not deliver alert to webhook")
    return devices, diff


def render(devices: list[Device], fmt: str, diff: ScanDiff | None = None) -> str:
    if fmt == "json":
        return render_json(devices)
    if fmt == "csv":
        return render_csv(devices)
    return render_table(devices, diff)


def cmd_scan(args: argparse.Namespace, inventory: Inventory) -> int:
    devices, diff = run_scan(args, inventory)
    output = render(devices, args.format, diff)
    print(output)
    if args.format == "table":
        print(f"\n{render_summary(devices, diff)}")
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    if args.fail_on_unknown and diff.unknown_new:
        return EXIT_UNKNOWN_DEVICE
    return 0


def cmd_watch(args: argparse.Namespace, inventory: Inventory) -> int:
    if args.interval < 10:
        raise DiscoveryError("--interval must be at least 10 seconds")
    log.info("watching %s every %ss (Ctrl+C to stop)", args.network, args.interval)
    try:
        while True:
            devices, diff = run_scan(args, inventory)
            log.info(render_summary(devices, diff))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("stopped")
    return 0


def cmd_devices(args: argparse.Namespace, inventory: Inventory) -> int:
    devices = sorted(inventory.devices.values(), key=lambda d: tuple(int(x) for x in d.ip.split(".")))
    if args.unknown:
        devices = [d for d in devices if not d.trusted]
    if not devices:
        print(f"no devices in {inventory.path}")
        return 0
    print(render(devices, args.format))
    return 0


def cmd_manage(args: argparse.Namespace, inventory: Inventory) -> int:
    if args.command == "trust":
        device = inventory.trust(args.mac, args.label)
        verb = "trusted"
    elif args.command == "untrust":
        device = inventory.untrust(args.mac)
        verb = "untrusted"
    else:
        device = inventory.remove(args.mac)
        verb = "forgot"
    inventory.save()
    print(f"{verb} {device.mac} ({device.ip}, {device.vendor})")
    return 0


COMMANDS = {
    "scan": cmd_scan,
    "watch": cmd_watch,
    "devices": cmd_devices,
    "trust": cmd_manage,
    "untrust": cmd_manage,
    "forget": cmd_manage,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    # Scapy logs a warning for every unanswered packet; keep the output clean.
    logging.getLogger("scapy").setLevel(logging.ERROR)

    try:
        inventory = Inventory.load(args.db)
        return COMMANDS[args.command](args, inventory)
    except (DiscoveryError, KeyError, ValueError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) else str(exc)
        log.error(message)
        return 1
    except PermissionError as exc:
        log.error("permission denied: %s", exc)
        return 1
