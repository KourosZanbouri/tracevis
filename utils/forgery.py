"""Detecting replies that were written by something other than the destination.

Backlog §2.12. Addressing a probe to `8.8.8.8` guarantees the destination
*field*, not the destination: an on-path box can answer in its place with a
spoofed source address, and nothing in the outgoing packet can prevent that —
literal addresses defeat resolution-time tampering only. The reply cannot hide,
though, because it has to come back, and when it does it carries evidence about
where it was really written.

Calibrated against a capture (kept locally, not published) of six probes taken
inside one minute against three destinations, each with a control (accessible
domain) and a treatment (blocked domain) arm. Every treatment arm was answered
by an interceptor while every control arm reached the real resolver, which makes
it a labelled positive *and* negative set rather than an anecdote.

Two signals are used. Both are properties of a single reply, so the detector
works on one measurement and does not need the A/B that produced it:

* **IP-ID reflection** — the reply carries the same IP ID as the query it
  answers. A real host generates its own; a box that mutates the request in
  place (swap addresses, flip QR, append an answer) leaves it untouched. It held
  on every forged reply and none of the genuine ones.
* **TTL implausibility** — a reply from a host `d` hops away should arrive with
  `initial_ttl - d`, and initial TTLs in the wild are 64, 128 or 255. The forged
  replies implied an initial TTL of 10, which nothing emits. Same mechanism as
  above: the query's TTL had been decremented to nothing by the time the box
  reflected it.

Deliberately *not* used, though the field write-up lists it as one: the
**DF flag**. It looked like a discriminator (forged replies had it clear) until
a genuine answer in the same capture also came back without it. Two of three is
not a signal.

Also not used, because neither is a property of one reply and both need a
baseline this module does not have: **RTT** and **DNS record TTL**, each of
which differed sharply between the forged and genuine replies. The tracer
records both anyway, so they remain available to anyone reading the JSON.
"""
from collections import namedtuple

# Initial TTLs in practice: 64 (Linux/BSD), 128 (Windows), 255 (network kit).
# A reply whose implied initial TTL falls below this is not something any stack
# emits — the forged replies imply 10. The threshold sits far below the lowest
# real value so an asymmetric return path, which can add hops the forward
# distance never saw, cannot push a genuine reply under it.
MIN_PLAUSIBLE_INITIAL_TTL = 32

# An IP ID of 0 is what Linux writes on DF packets, so a 0==0 "match" says
# nothing about who composed the reply.
IGNORED_IP_ID = 0

ForgerySignal = namedtuple("ForgerySignal", ["forged", "evidence"])

NO_FORGERY = ForgerySignal(forged=False, evidence="")


def _as_int(value):
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def is_ip_id_reflected(sent_id, received_id):
    """True when a reply carries the IP ID of the query it answers.

    The strong signal: ~1 in 65536 per probe by chance, and it was exact on all
    three forged replies in the reference capture.
    """
    sent, received = _as_int(sent_id), _as_int(received_id)
    if sent is None or received is None:
        return False
    if sent == IGNORED_IP_ID or received == IGNORED_IP_ID:
        return False
    return sent == received


def implied_initial_ttl(reply_ttl, hop_distance):
    """The initial TTL a reply must have started with to arrive as it did."""
    reply_ttl, hop_distance = _as_int(reply_ttl), _as_int(hop_distance)
    if reply_ttl is None or hop_distance is None or reply_ttl <= 0:
        return None
    return reply_ttl + hop_distance


def is_reply_ttl_implausible(reply_ttl, hop_distance):
    """True when no real stack could have emitted a reply that arrived like this.

    `hop_distance` is the TTL step at which the destination answered, i.e. how
    far away it is on the forward path.
    """
    implied = implied_initial_ttl(reply_ttl, hop_distance)
    if implied is None:
        return False
    return implied < MIN_PLAUSIBLE_INITIAL_TTL


def classify_reply(sent_ip=None, received_ip=None, hop_distance=None):
    """Judge one reply. `sent_ip`/`received_ip` are the saved IP-header dicts."""
    sent_ip = sent_ip or {}
    received_ip = received_ip or {}
    evidence = []
    if is_ip_id_reflected(sent_ip.get("id"), received_ip.get("id")):
        evidence.append("ip-id-reflected")
    if is_reply_ttl_implausible(received_ip.get("ttl"), hop_distance):
        implied = implied_initial_ttl(received_ip.get("ttl"), hop_distance)
        evidence.append(f"reply-ttl-implausible(implied-initial={implied})")
    # Either signal alone is enough. They are independent — one is about who
    # composed the packet, the other about how far it travelled — so requiring
    # both would discard a detection whenever an interceptor happens to fix up
    # one of them, and an interceptor that fixes up *both* defeats either rule.
    return ForgerySignal(forged=bool(evidence), evidence=",".join(evidence))


def find_forged_destination_reply(entry):
    """Judge the destination's answer in one `traceroute_data`-shaped entry.

    Reads the hops the tracer already saved, so an existing measurement can be
    re-examined without re-tracing. Only replies that claim to come *from the
    destination* are judged: an intermediate hop's ICMP is a different thing and
    legitimately carries the quoted packet's own fields.
    """
    destination = getattr(entry, "dst_addr", None) or ""
    for hop_entry in getattr(entry, "result", []) or []:
        for result in hop_entry.get("result", []):
            if not isinstance(result, dict) or result.get("from") != destination:
                continue
            packets = result.get("packets") or {}
            received = packets.get("received") or []
            if not received:
                continue
            signal = classify_reply(
                sent_ip=(packets.get("sent") or {}).get("IP"),
                received_ip=received[0].get("IP"),
                hop_distance=hop_entry.get("hop"),
            )
            if signal.forged:
                return signal
    return NO_FORGERY
