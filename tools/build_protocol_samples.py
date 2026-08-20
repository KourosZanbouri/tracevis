#!/usr/bin/env python3
"""Generate the protocol-shape samples (WireGuard / Shadowsocks / gRPC-h2c).

Three protocols with no probe shape in `samples/`:
WireGuard ("blackholed post-handshake", "immediate handshake detection"),
Shadowsocks ("working, less inspected") and gRPC on 443 ("highly unstable";
"non-TLS patterns trigger RST"). Each sample here is a **controlled A/B**: two
probes that differ in exactly one thing, so a difference in outcome has one
explanation.

Run from the repository root:  python3 tools/build_protocol_samples.py
"""
import base64
import json
import os
import secrets

from scapy.all import IP, TCP, UDP, Raw, hexdump

import utils.sni

SRC = "127.1.2.7"                     # what `_read_pasted_packet` anonymises to
CONTROL_SNI = "hcaptcha.com"          # Phase 2's one named SNI
REFRESHED_POOL = "1.1.1.1,104.16.133.229,142.251.36.14,151.101.1.57"
KNOWN_GOOD_TCP = "1.1.1.1"            # the only destination a run has been seen
                                      # complete a TCP handshake


def wireguard_handshake_initiation():
    """A WireGuard handshake initiation message (whitepaper §5.4.2), 148 bytes.

    type(1) + reserved(3) + sender_index(4) + ephemeral(32) +
    encrypted_static(48) + encrypted_timestamp(28) + mac1(16) + mac2(16).

    The crypto fields are random: no key material is available and none is
    needed. A DPI that fingerprints WireGuard keys on the leading `01 00 00 00`
    and the fixed 148-byte length, which this reproduces exactly.
    """
    message = (b"\x01" + b"\x00\x00\x00"          # type=1, reserved
               + secrets.token_bytes(4)           # sender_index
               + secrets.token_bytes(32)          # unencrypted_ephemeral
               + secrets.token_bytes(48)          # encrypted_static
               + secrets.token_bytes(28)          # encrypted_timestamp
               + secrets.token_bytes(16)          # mac1
               + secrets.token_bytes(16))         # mac2
    assert len(message) == 148, len(message)
    return message


def shadowsocks_aead_opening():
    """The opening bytes of a Shadowsocks AEAD stream: indistinguishable noise.

    Wire format is [salt][encrypted length + tag][encrypted payload + tag] with
    no header, magic or version — the design goal is that it looks like nothing.
    32-byte salt (chacha20-ietf-poly1305) + an 18-byte length block + a short
    encrypted chunk is a faithful *shape*, which is all a reachability probe can
    test.
    """
    return (secrets.token_bytes(32)               # salt
            + secrets.token_bytes(2 + 16)         # encrypted length + tag
            + secrets.token_bytes(48 + 16))       # encrypted chunk + tag


def http2_cleartext_preface():
    """The h2c connection preface plus an empty SETTINGS frame.

    port 443 is deep-inspected and "non-TLS patterns trigger RST".
    This is the cleanest available non-TLS pattern — a well-formed HTTP/2 opener
    that any TLS parser rejects immediately.
    """
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = b"\x00\x00\x00" + b"\x04" + b"\x00" + b"\x00\x00\x00\x00"
    return preface + settings


def encode(packet):
    """Freeze a packet the way `samples/*.conf` stores them."""
    text = hexdump(packet, dump=True)
    return "b64:" + base64.b64encode(text.encode()).decode()


def tcp_probe(dport, payload):
    return (IP(src=SRC, dst=KNOWN_GOOD_TCP, flags="DF")
            / TCP(sport=54321, dport=dport, flags="PA", seq=0, ack=0,
                  window=8192,
                  options=[("MSS", 1460), ("SAckOK", b""),
                           ("Timestamp", (0, 0)), ("NOP", None), ("WScale", 7)])
            / Raw(payload))


def udp_probe(dport, payload):
    return (IP(src=SRC, dst="1.1.1.1", flags="DF")
            / UDP(sport=54321, dport=dport) / Raw(payload))


def config(name, annot1, annot2, ips, packet1, packet2, handshake):
    return {
        "annot1": annot1,
        "annot2": annot2,
        "attach": False,
        "continue": False,
        "csv": False,
        "csvraw": False,
        "dns": False,
        "dnsdot": False,
        "dnstcp": False,
        "dnstt": False,
        "domain1": None,
        "domain2": None,
        "file": None,
        "iface": None,
        "ips": ips,
        "label": None,
        "maxttl": 20,
        "name": name,
        "network_mode": "auto",
        "options": "new",
        "packet": True,
        "packet_data": {
            "add_firewall_drop": False,
            "packet1": {"handshake": handshake, "hex": encode(packet1)},
            "packet2": {"handshake": handshake, "hex": encode(packet2)},
        },
        "packet_input_method": "json",
        # paris:false is load-bearing — `from_json` never sets do_tcph under
        # retransmission mode, and a failed preflight replays a bare SYN.
        "paris": False,
        "port": None,
        "port_pool": None,
        "repeat": 1,
        "rexmit": False,
        "ripe": None,
        "ripemids": None,
        "vps": None,
        "ioda_country": None,
        "ipv4": False,
        "show_ifaces": False,
        "sni_test": False,
        "timeout": None,
        "timeout_profile": "degraded",
        "adaptive_timeout": False,
    }


def main():
    hello = utils.sni.build_tls_clienthello(CONTROL_SNI)

    samples = {
        # A/B on payload shape, same host, same port, both handshaking. The
        # control is the hello --sni-test already puts on the wire, and
        # 1.1.1.1:443 is the one arm observed completing a handshake.
        "grpc-h2c.conf": config(
            name="grpc-h2c",
            annot1=f"TLS ClientHello SNI={CONTROL_SNI} :443 (control)",
            annot2="HTTP/2 cleartext preface :443 (non-TLS on 443)",
            ips=KNOWN_GOOD_TCP,
            packet1=tcp_probe(443, hello),
            packet2=tcp_probe(443, http2_cleartext_preface()),
            handshake=True),
        "shadowsocks.conf": config(
            name="shadowsocks",
            annot1=f"TLS ClientHello SNI={CONTROL_SNI} :443 (control)",
            annot2="Shadowsocks AEAD opening bytes :443 (high-entropy, headerless)",
            ips=KNOWN_GOOD_TCP,
            packet1=tcp_probe(443, hello),
            packet2=tcp_probe(443, shadowsocks_aead_opening()),
            handshake=True),
        # UDP, so no handshake and no retry ladder — cheap enough for the full
        # pool. A/B is header pattern vs same-length noise on the same port.
        "wireguard.conf": config(
            name="wireguard",
            annot1="WireGuard handshake initiation :51820 (type 1, 148B)",
            annot2="same-length random UDP :51820 (control)",
            ips=REFRESHED_POOL,
            packet1=udp_probe(51820, wireguard_handshake_initiation()),
            packet2=udp_probe(51820, secrets.token_bytes(148)),
            handshake=False),
    }

    for filename, blob in samples.items():
        path = os.path.join("samples", filename)
        with open(path, "w") as handle:
            json.dump(blob, handle, indent=4, sort_keys=True)
            handle.write("\n")
        print("wrote", path)


if __name__ == "__main__":
    main()
