#!/usr/bin/env python3
"""SNI filtering test probes for traceroute-based censorship measurement.

to map the SNI blocklist, send a TCP SYN to port 443, complete
the handshake, and then send a TLS ClientHello containing the target SNI in
the Server Name Indication extension. A DPI layer that has extracted the SNI
will drop or RST the flow based on a blocklist; a clean path allows it through
to the destination.

TraceVis builds these packets with scapy (no scapy-tls dependency): the raw
TLS ClientHello bytes are placed in a ``Raw`` layer on a ``TCP/443`` probe,
and the existing ``do_tcph1`` handshake path in ``utils/trace.py`` handles the
3-way exchange and data delivery.
"""

import os
import struct

from scapy.all import IP, TCP, Raw


def build_tls_clienthello(sni_hostname: str) -> bytes:
    """Build the wire bytes of a TLS 1.2 ClientHello containing *sni_hostname*.

    The ClientHello is RFC 8446 (TLS 1.2 variant) compliant enough for a real
    TLS server or a DPI/TLS-parser to extract the SNI extension. Returns the
    TLS *record layer* bytes (content-type byte included).
    """
    sni_bytes = sni_hostname.encode("ascii")

    cipher_suites = [
        0x1301,  # TLS_AES_256_GCM_SHA384
        0x1302,  # TLS_CHACHA20_POLY1305_SHA256
        0x1303,  # TLS_AES_128_GCM_SHA256
        0x002f,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0x0035,  # TLS_RSA_WITH_AES_128_CBC_SHA
    ]
    cipher_bytes = b"".join(struct.pack("!H", c) for c in cipher_suites)

    # --- SNI extension ---
    sn_name = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sn_list = struct.pack("!H", len(sn_name)) + sn_name
    sn_ext = sn_list
    sni_ext = b"\x00\x00" + struct.pack("!H", len(sn_ext)) + sn_ext

    # --- supported_versions extension (TLS 1.2 + 1.3) ---
    # In ClientHello, supported_versions is in the extensions block (not as
    # a separate extension in the legacy version field). RFC 8446 §4.2.1:
    # `ProtocolVersion versions<2..254>` — a *1-byte* list length comes first.
    supported_versions = b"\x03\x03" + b"\x03\x04"  # TLS 1.2, TLS 1.3
    sv_data = struct.pack("!B", len(supported_versions)) + supported_versions
    sv_ext = b"\x00\x2b" + struct.pack("!H", len(sv_data)) + sv_data

    # --- signature_algorithms extension ---
    # RFC 8446 §4.2.3: `SignatureScheme supported_signature_algorithms<2..2^16-2>`
    # — a 2-byte list length precedes the scheme pairs.
    sig_algs = b"\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x07\x06"  # ecdsa/rsa_pss/rsa_pkcs1
    sig_data = struct.pack("!H", len(sig_algs)) + sig_algs
    sig_ext = b"\x00\x0d" + struct.pack("!H", len(sig_data)) + sig_data

    # --- supported_groups extension (RFC 8422 §5.1.1; ext type 0x000a) ---
    # 2-byte list length then 2-byte NamedGroup ids.
    groups = b"\x00\x1d" + b"\x00\x17" + b"\x00\x18"  # x25519, secp256r1, secp384r1
    groups_data = struct.pack("!H", len(groups)) + groups
    groups_ext = b"\x00\x0a" + struct.pack("!H", len(groups_data)) + groups_data

    # --- ec_point_formats extension (ext type 0x000b) ---
    # 1-byte list length then the formats; `00` is uncompressed.
    ec_points = b"\x00"
    ec_data = struct.pack("!B", len(ec_points)) + ec_points
    ec_ext = b"\x00\x0b" + struct.pack("!H", len(ec_data)) + ec_data

    extensions = sni_ext + sv_ext + sig_ext + groups_ext + ec_ext

    # --- ClientHello body ---
    body = b""
    body += b"\x03\x03"                    # legacy_version: TLS 1.2
    body += os.urandom(32)                # random
    body += b"\x00"                        # legacy_session_id_length: 0
    body += struct.pack("!H", len(cipher_bytes))  # cipher_suites_length
    body += cipher_bytes                   # cipher_suites
    body += b"\x01"                        # legacy_compression_methods_length
    body += b"\x00"                        # compression_method: null
    body += struct.pack("!H", len(extensions))  # extensions_length
    body += extensions

    # --- Handshake message: type(1B) + length(3B) + body ---
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body

    # --- TLS record layer: content_type(1B) + version(2B) + length(2B) + data ---
    record = b"\x16" + b"\x03\x03" + struct.pack("!H", len(handshake)) + handshake
    return record


def make_sni_probe(resolver_ip, sni_hostname, ttl=1):
    """Build a TCP/443 probe carrying a TLS ClientHello with the given SNI.

    Returns ``(packet, accessible_address, blocked_address)`` — the same
    3-tuple shape the ``--dns`` family of helpers returns, so the tracer's
    request_packet_1/annotation wiring is unchanged.

    The packet is constructed with a SYN flag so the TCP handshake path
    (``do_tcph1``) can be used: scapy sends SYN → gets SYN-ACK → sends ACK
    → then sends the same packet as data (with the TLS ClientHello in the
    Raw layer). The response to the ClientHello reveals SNI filtering.
    """
    clienthello = build_tls_clienthello(sni_hostname)
    packet = (
        IP(dst=str(resolver_ip), id=1, ttl=ttl)
        / TCP(sport=53, dport=443, seq=0, flags="PA",
              options=[("MSS", 1460), ("SAckOK", b''),
                       ("Timestamp", (0, 0)), ("NOP", None),
                       ("WScale", 7)])
        / Raw(load=clienthello)
    )
    return packet, sni_hostname, None


def make_sni_packets(blocked_address="", accessible_address="", ttl=1):
    """Build the (accessible, blocked) SNI probe pair, mirroring get_dns_packets.

    - ``accessible_address`` — an SNI expected to be *allowed* (e.g. example.com)
    - ``blocked_address`` — an SNI expected to be *filtered* (e.g. a sensitive domain)
    """
    if blocked_address == "":
        blocked_address = "www.google.com"
    if accessible_address == "":
        accessible_address = "www.example.com"
    resolver = "1.1.1.1"
    packet_1, _, _ = make_sni_probe(resolver, accessible_address, ttl=ttl)
    packet_2, _, _ = make_sni_probe(resolver, blocked_address, ttl=ttl)
    return packet_1, accessible_address, packet_2, blocked_address
