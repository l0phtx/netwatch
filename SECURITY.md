# Security Policy

Please report security problems privately through GitHub's
[private vulnerability reporting](https://github.com/l0phtx/netwatch/security/advisories/new)
instead of opening a public issue. I aim to reply within 7 days.

NetWatch needs root to send ARP packets. Run it from a virtual environment you
control, and keep the inventory file readable only by the account that runs scans:
it lists every device and open port on your network.
