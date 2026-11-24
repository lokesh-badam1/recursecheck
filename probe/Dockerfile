FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends dnsutils iputils-ping iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir dnspython pyyaml jinja2
WORKDIR /work
