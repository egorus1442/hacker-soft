FROM debian:bookworm-slim AS pd-tools

ARG TARGETARCH
ARG SUBFINDER_VERSION=2.14.0
ARG DNSX_VERSION=1.2.3
ARG HTTPX_VERSION=1.9.0
ARG NAABU_VERSION=2.6.1
ARG KATANA_VERSION=1.6.1
ARG NUCLEI_VERSION=3.9.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64|arm64) arch="${TARGETARCH}" ;; \
        *) echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    install_tool() { \
        name="$1"; \
        repo="$2"; \
        version="$3"; \
        archive="${name}_${version}_linux_${arch}.zip"; \
        url="https://github.com/projectdiscovery/${repo}/releases/download/v${version}/${archive}"; \
        curl -fsSL --retry 5 --retry-delay 3 --connect-timeout 20 --max-time 300 -o "/tmp/${archive}" "${url}"; \
        unzip -q "/tmp/${archive}" -d "/tmp/${name}"; \
        install -m 0755 "/tmp/${name}/${name}" "/usr/local/bin/${name}"; \
        rm -rf "/tmp/${archive}" "/tmp/${name}"; \
    }; \
    install_tool subfinder subfinder "${SUBFINDER_VERSION}"; \
    install_tool dnsx dnsx "${DNSX_VERSION}"; \
    install_tool httpx httpx "${HTTPX_VERSION}"; \
    install_tool naabu naabu "${NAABU_VERSION}"; \
    install_tool katana katana "${KATANA_VERSION}"; \
    install_tool nuclei nuclei "${NUCLEI_VERSION}"; \
    subfinder -version; \
    dnsx -version; \
    httpx -version; \
    naabu -version; \
    katana -version; \
    nuclei -version

RUN set -eux; \
    nuclei -update-templates -update-template-dir /opt/nuclei-templates; \
    template_count="$(find /opt/nuclei-templates -name '*.yaml' | wc -l)"; \
    echo "nuclei templates: ${template_count}"; \
    [ "${template_count}" -gt 100 ]

ARG AMASS_VERSION=5.1.1

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64|arm64) arch="${TARGETARCH}" ;; \
        *) echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    archive="amass_linux_${arch}.tar.gz"; \
    url="https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/${archive}"; \
    curl -fsSL --retry 5 --retry-delay 3 --connect-timeout 20 --max-time 300 -o "/tmp/${archive}" "${url}"; \
    mkdir -p /tmp/amass; \
    tar -xzf "/tmp/${archive}" -C /tmp/amass; \
    install -m 0755 "$(find /tmp/amass -type f -name amass | head -n 1)" /usr/local/bin/amass; \
    rm -rf "/tmp/${archive}" /tmp/amass; \
    amass -version

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates dnsutils libpcap0.8 openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=pd-tools /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=pd-tools /usr/local/bin/dnsx /usr/local/bin/dnsx
COPY --from=pd-tools /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=pd-tools /usr/local/bin/naabu /usr/local/bin/naabu
COPY --from=pd-tools /usr/local/bin/katana /usr/local/bin/katana
COPY --from=pd-tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=pd-tools /usr/local/bin/amass /usr/local/bin/amass
COPY --from=pd-tools /opt/nuclei-templates /opt/nuclei-templates

ENV HACKER_SOFT_NUCLEI_TEMPLATES=/opt/nuclei-templates

COPY pyproject.toml README.md ./
COPY hacker_soft ./hacker_soft

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

CMD ["python", "-m", "hacker_soft.bot"]
