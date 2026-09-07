# Linux CIS Hardening Auditor -- container image
# The image runs the auditor in its default READ-ONLY mode. To audit a host,
# mount it read-only and point --root at the mount:
#   docker run --rm -v /:/host:ro cis-auditor audit --root /host --no-save
FROM python:3.11-slim

# Tools some live checks shell out to (all read-only): ss, ip, sshd -t.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
COPY checks ./checks
COPY templates ./templates
COPY tests ./tests
COPY scripts ./scripts

RUN pip install --no-cache-dir -e .

# Reports/backups live under /app by default; expose as a volume for demos.
VOLUME ["/app/reports"]

# Drop privileges for the default (read-only) usage.
RUN useradd --create-home auditor && chown -R auditor:auditor /app
USER auditor

ENTRYPOINT ["python", "-m", "app"]
CMD ["--help"]
