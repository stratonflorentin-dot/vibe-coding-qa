# Official Kali Linux rolling image, pinned to the verified manifest-list digest.
# The digest below was resolved from docker.io/kalilinux/kali-rolling on
# 2026-11-11; update it deliberately and review package changes before rollout.
FROM kalilinux/kali-rolling@sha256:6ec743d9fc5cd397451eeddeff3869bcfab5de9bd5dec5b1f34cbfbd80313073

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/vcqa \
    VCQA_WORKER_HOST=0.0.0.0 \
    VCQA_WORKER_PORT=8765 \
    VCQA_NUCLEI_TEMPLATES=/opt/vcqa/nuclei-templates

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ca-certificates nmap nuclei whatweb testssl.sh \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /home/vcqa --shell /usr/sbin/nologin vcqa \
    && install -d -o vcqa -g vcqa /work /tmp/vcqa /opt/vcqa/nuclei-templates

WORKDIR /opt/vcqa
COPY --chown=vcqa:vcqa security_worker /opt/vcqa/security_worker
USER 10001:10001

EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=2)"

ENTRYPOINT ["python3", "-m", "security_worker.server"]
