# lanowl — the monitor's image (amd64 and arm64).
#
# What does not come inside: the model. It runs in Ollama wherever the GPU is,
# often another machine, and lanowl calls it over HTTP (model.url / LANOWL_MODEL_URL).
FROM python:3.12-slim

# snmp       router telemetry (snmpget): enrichment only, lanowl degrades gracefully without it
# openssh    host logs, backups, updates, reboots: ssh with a key or with secrets.yaml's logins
# ping       a fallback: icmplib does the real work (it needs net.ipv4.ping_group_range on the
#            host, or every device reads DOWN — see the README)
# nmap       the model's proposed scans, run only when the owner approves (-sT/-sV: no raw socket)
# mtr traceroute dig whois curl fping tcpdump arping — the model's diagnostics (checks.py); with
#            host networking on Linux they see the real path and the real wire
# tzdata     NOT optional: sunrise/sunset and the router's log timestamps read local time (TZ)
RUN apt-get update && apt-get install -y --no-install-recommends \
        snmp iputils-ping openssh-client ca-certificates tzdata nmap \
        mtr-tiny traceroute bind9-dnsutils whois curl fping tcpdump iputils-arping \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LANOWL_CONFIG=/config/config.yaml \
    LANOWL_INVENTORY=/config/inventory.yaml

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir .
# the test suite rides along: `docker run --rm lanowl python /app/tests/run_all.py` gates a deploy
COPY tests/ ./tests/

# /config  config.yaml, inventory.yaml, secrets.yaml (mount it read-only)
# /state   everything lanowl writes — every relative path in config.yaml lands here
VOLUME ["/state"]
WORKDIR /state
EXPOSE 80
CMD ["python", "-m", "lanowl.main"]
