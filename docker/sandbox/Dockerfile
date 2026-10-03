# The model's shell (shell.py) — a sandbox beside lanowl.
#
# lanowl's own container is never the place for a model's shell: it holds the ssh keys, the
# logins and the bot token, and the model reads text strangers write. This one holds NOTHING —
# no key, no config, no state — and cannot reach what matters:
#
#   - its firewall (entrypoint.sh) is set by root at every start, before anything else runs,
#     in this container's own network namespace; then every capability that could change it
#     is dropped for good. From the LAN, the VPN sites and the overlays it gets ICMP, DNS,
#     traceroute and a TCP handshake — a port reads open or closed — but the packet after the
#     handshake is dropped: no HTTP GET to a Shelly, no MQTT publish, no login. lanowl's host
#     itself (the dashboard, sshd) is unreachable. The internet is open, rate-limited on new
#     connections;
#   - commands run as uid 10001 with one capability, NET_RAW (ping, mtr, nmap), on a
#     read-only filesystem; /work and /tmp are small tmpfs;
#   - lanowl reaches it only through a unix socket on a shared volume (server.py) — never the
#     Docker socket, which would be root on the host and so the secrets.
#
# lanowl proves the isolation itself (Shell.canary) and offers the tool only while the proof
# holds: a handshake to a LAN service works, the GET after it times out, lanowl's host is
# unreachable — and, for the offline sandbox, the internet and every resolver too.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates iptables iproute2 iputils-ping iputils-tracepath mtr-tiny \
        traceroute bind9-dnsutils whois curl wget nmap fping netcat-openbsd openssl jq \
        python3 procps less \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --home-dir /work --no-create-home --shell /bin/bash sandbox

COPY docker/sandbox/entrypoint.sh docker/sandbox/server.py /opt/sandbox/
RUN chmod 755 /opt/sandbox/entrypoint.sh && chmod 644 /opt/sandbox/server.py

ENTRYPOINT ["/opt/sandbox/entrypoint.sh"]
