# syntax=docker/dockerfile:1
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    TRACEVIS_OUTPUT_DIR=/tracevis_data/

WORKDIR /tracevis

# Install requirements before copying whole source. (used for quick build)
COPY requirements.txt .

# Runtime deps (scapy, pyvis) plus `iptables`, which `--add-firewall-drop`
# shells out to so the kernel does not RST the handshake TraceVis is driving.
#
# Raw sockets come from the *container's* capabilities at run time, not from
# file capabilities on the interpreter: run with
# `--cap-add NET_RAW --cap-add NET_ADMIN` (or `--privileged`), as documented in
# the README. Do not `setcap` the python binary here — a file with an effective
# capability the container's bounding set lacks (NET_ADMIN is not in Docker's
# default set) makes every `execve` of that interpreter fail with EPERM
# ("exec /usr/local/bin/python: operation not permitted"), for root as well.
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get update && \
    apt-get install -y --no-install-recommends iptables && \
    rm -rf /var/lib/apt/lists/*

COPY . .

ENTRYPOINT [ "python", "tracevis.py" ]

CMD [ "-h" ]
