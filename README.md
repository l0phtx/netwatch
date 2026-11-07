# NetWatch

[![CI](https://github.com/l0phtx/netwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/l0phtx/netwatch/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

NetWatch maps every device on a local network and alerts you when an unknown one joins.

It sweeps a subnet with ARP, looks up each device's hardware vendor, checks for open TCP ports and keeps an inventory of what it has seen. Mark the devices you know as trusted. After that, NetWatch reports anything new: a rogue Raspberry Pi under a desk, a guest laptop on the staff VLAN, or a printer that suddenly opens RDP.

```
$ sudo netwatch scan 192.168.1.0/24
IP             MAC                VENDOR                    HOSTNAME        OPEN PORTS     STATUS
-------------  -----------------  ------------------------  --------------  -------------  -------
192.168.1.1    3c:84:6a:12:9e:01  TP-LINK TECHNOLOGIES CO.  Gateway         53,80,443      trusted
192.168.1.20   00:11:32:5a:7c:3d  Synology Incorporated     NAS             22,445,5000    trusted
192.168.1.31   a4:5e:60:c1:02:9f  Apple, Inc.               macbook.lan     -              trusted
192.168.1.48   dc:a6:32:7b:44:10  Raspberry Pi Trading Ltd  -               22,8080        NEW
192.168.1.112  9e:3b:21:f0:aa:07  Private (randomized MAC)  -               -              NEW

5 devices up, 2 new (2 unknown)
12:04:31 WARNING NetWatch alert for 192.168.1.0/24:
- NEW unknown device 192.168.1.48 (dc:a6:32:7b:44:10, Raspberry Pi Trading Ltd)
- NEW unknown device 192.168.1.112 (9e:3b:21:f0:aa:07, Private (randomized MAC))
```

*Example output; addresses are illustrative.*

## Features

- **Host discovery** with ARP, which finds devices that block ping and every other probe.
- **Vendor lookup** from the MAC address (IEEE OUI database bundled with Scapy). Randomized phone and laptop MACs are flagged as such instead of shown as "Unknown".
- **Concurrent TCP port checks** across all hosts at once, with a sensible default port list or your own (`22,80,8000-8100`).
- **Reverse DNS** names, resolved in parallel.
- **Device inventory** in a JSON file: first seen, last seen, IP, ports, trust state and a friendly label.
- **Change detection**: new devices, IP changes, newly opened ports and devices that went missing.
- **Alerts** to the console and to any Slack, Google Chat or Mattermost incoming webhook.
- **Output** as a table, JSON or CSV, and an exit code for cron and CI jobs.
- Only one dependency (Scapy). No database, no daemon and no cloud account.

## Install

NetWatch needs Python 3.10+ and root privileges for the ARP sweep (raw sockets). It runs on Linux and macOS.

```bash
git clone https://github.com/l0phtx/netwatch.git
cd netwatch
python3 -m venv .venv
.venv/bin/pip install .
sudo .venv/bin/netwatch --help
```

## Usage

### 1. Build a baseline

Scan once and trust everything that is on the network right now:

```bash
sudo netwatch scan 192.168.1.0/24 --trust-new
```

Then give the important devices a name:

```bash
netwatch trust 3c:84:6a:12:9e:01 --label "Gateway"
netwatch trust 00:11:32:5a:7c:3d --label "NAS"
```

### 2. Scan and review changes

```bash
sudo netwatch scan 192.168.1.0/24            # table + summary
sudo netwatch scan 192.168.1.0/24 -f json -o scan.json
sudo netwatch scan 192.168.1.0/24 -p 22,3389,5900 --no-dns
netwatch devices --unknown                   # every device not yet trusted
```

### 3. Watch continuously

```bash
export NETWATCH_WEBHOOK="https://chat.googleapis.com/v1/spaces/.../messages?key=..."
sudo -E netwatch watch 192.168.1.0/24 --interval 300
```

### Commands

| Command | What it does |
| --- | --- |
| `scan NETWORK` | Scan once, update the inventory, print results and alert on unknown devices |
| `watch NETWORK` | Run `scan` every `--interval` seconds until stopped |
| `devices` | List the inventory (`--unknown` for untrusted devices only) |
| `trust MAC [--label NAME]` | Mark a device as known |
| `untrust MAC` | Mark a device as unknown again |
| `forget MAC` | Remove a device from the inventory |

Useful options for `scan` and `watch`:

| Option | Default | Description |
| --- | --- | --- |
| `-p, --ports` | `common` | `common`, `none`, or a list such as `22,80,8000-8100` |
| `-i, --iface` | auto | Interface to send ARP requests on |
| `--arp-timeout` | `2` | Seconds to wait for ARP replies |
| `--port-timeout` | `0.5` | TCP connect timeout per port |
| `--workers` | `200` | Concurrent port checks |
| `--no-dns` | off | Skip reverse DNS lookups |
| `--webhook URL` | `$NETWATCH_WEBHOOK` | Send alerts to a chat webhook |
| `--trust-new` | off | Trust every new device (baseline mode) |
| `--fail-on-unknown` | off | `scan` exits with code `3` if an unknown device is found |

The inventory is written to `./netwatch.json` with permissions `0600`. Change the path with `--db PATH` or `NETWATCH_DB`.

### Scheduled scans

Run a scan every 15 minutes with cron and alert to a webhook:

```cron
*/15 * * * * NETWATCH_DB=/var/lib/netwatch/office.json /opt/netwatch/.venv/bin/netwatch scan 10.10.0.0/24 --webhook https://hooks.slack.com/services/... >> /var/log/netwatch.log 2>&1
```

## How it works

```
             +-------------------+     ARP who-has 192.168.1.0/24
  netwatch ->|  discovery.py     |---------------------------------> LAN
             |  ARP sweep (Scapy)|<--------------------------------- is-at replies
             +---------+---------+
                       | devices (IP, MAC)
          +------------+-------------+
          v            v             v
     vendor.py     ports.py     discovery.py
     OUI lookup    TCP connect  reverse DNS
                   (thread pool)
          +------------+-------------+
                       v
             +-------------------+     diff: new / IP changed /
             |  inventory.py     |---- ports changed / missing
             |  netwatch.json    |
             +---------+---------+
                       v
             report.py (table/JSON/CSV)  +  alerts.py (console/webhook)
```

1. **Discovery.** NetWatch broadcasts an ARP request for every address in the subnet. Every host that wants to use IPv4 on the LAN must answer ARP, so this finds devices that a ping sweep misses.
2. **Enrichment.** The first three bytes of a MAC address (the OUI) identify the manufacturer. If the "locally administered" bit is set, the MAC is randomized, which is normal for modern phones.
3. **Port checks.** Each `(host, port)` pair is a full TCP connect in a thread pool. This needs no extra privileges and gives accurate open/closed results.
4. **Inventory and diff.** Devices are keyed by MAC address, because IPs change with DHCP. The inventory is written atomically (temp file + rename), so an interrupted scan never corrupts it.
5. **Alerting.** Only unknown devices and newly opened ports raise an alert. Closed ports and trusted devices stay quiet, which keeps the noise low.

## Limitations

- ARP only works on the local broadcast domain. To watch another VLAN, run NetWatch on a host inside it.
- MAC addresses can be spoofed. Use NetWatch for visibility, not as an access control. Pair it with 802.1X or port security for enforcement.
- IPv6-only devices are not discovered.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest --cov=netwatch     # unit tests, no root or network needed
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy src
```

```
src/netwatch/
├── cli.py         argument parsing and commands
├── discovery.py   ARP sweep and reverse DNS
├── vendor.py      MAC vendor lookup
├── ports.py       concurrent TCP port checks
├── inventory.py   JSON inventory and change detection
├── alerts.py      alert text and webhook delivery
├── report.py      table, JSON and CSV output
└── models.py      Device and ScanDiff dataclasses
```

## Legal

Only scan networks that you own or have written permission to test. Unauthorized scanning may break the law or your organization's policy.

## License

[MIT](LICENSE)
