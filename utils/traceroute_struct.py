#!/usr/bin/env python3
import json

import utils.convert_packetlist


class traceroute_data:
    def __init__(
        self, dst_addr: str, annotation: str, proto: str, port: int, timestamp: int,
        src_addr: str = "127.0.0.2", from_ip: str = "127.0.0.1",
        prb_id: int = -1, msm_id: int = -1, msm_name: str = "traceroute",
        ttr: float = -1, af: int = 4, lts: int = -1, paris_id: int = -1,
        size: int = -1, dst_name: str = "",
         network_asn: str = "", network_name: str = "", country_code: str = "",
        city: str = '',
         dpi_cleared: bool = False, cgnat_hop: bool = False,
         sni_inspected: bool = False, rst_flood: bool = False,
         tcp_silently_dropped: bool = False, network_state: str = "",
         provider_status: str = "", reply_forged: bool = False,
         forgery_evidence: str = ""
      ) -> None:
        self.af = af
        self.dst_addr = dst_addr
        self.dst_name = dst_name
        self.annotation = annotation
        self.endtime = -1
        self.from_ip = from_ip
        self.lts = lts
        self.msm_id = msm_id
        self.msm_name = msm_name
        self.paris_id = paris_id
        self.prb_id = prb_id
        self.proto = proto
        self.port = port
        self.result = []
        self.size = size
        self.src_addr = src_addr
        self.timestamp = timestamp
        self.ttr = ttr
        self.asn = network_asn
        self.asname = network_name
        self.cc = country_code
        self.city = city
        self.dpi_cleared = dpi_cleared
        self.cgnat_hop = cgnat_hop
        self.sni_inspected = sni_inspected
        self.rst_flood = rst_flood
        self.tcp_silently_dropped = tcp_silently_dropped
        # What `utils.geolocate.classify_network_state` concluded. Recorded
        # because the flags above are not a substitute for it: `vis.py` used to
        # reconstruct the regime from `cgnat_hop`, which only worked while
        # `cgnat_hop` *was* the regime and stops being true once it reports
        # observed CGNAT instead.
        self.network_state = network_state
        # Which metadata providers answered, e.g.
        # `cloudflare=silent,ipinfo=ok,ifconfig=ok`. The evidence behind
        # `network_state`: a differential in *this* is what says "allowlisted"
        # when DNS is not being hijacked, and without it a saved capture cannot
        # be re-read to find out why it was classified the way it was.
        self.provider_status = provider_status
        # Backlog §2.12: the destination's answer was written by something
        # other than the destination. `forgery_evidence` names which signals
        # fired, because a bare boolean about someone forging your traffic is
        # not a claim anyone should have to take on trust.
        self.reply_forged = reply_forged
        self.forgery_evidence = forgery_evidence

    def add_hop(self, hop, from_ip, rtt, size, ttl, answer_summary, answered, unanswered, rst_count=0, dport=None):
        if len(self.result) < hop:
            (self.result).append({"hop": hop, "result": []})
        if rtt == 0:
            self.result[hop - 1]["result"].append({
                "x": "-",
            })
        elif from_ip == "***":
            packetlist = utils.convert_packetlist.packetlist2json(
                answered, unanswered, self.from_ip)
            star_result = {
                "x": "*",
                "packets": packetlist,
            }
            # A hop can be a star *and* carry evidence: a TCP handshake refused
            # by an injected RST or an ICMP prohibited sends no data packet, so
            # there is no answer to report, but there is very much something to
            # record. Both keys stay absent when there is nothing to say, so a
            # plain timeout serialises exactly as it always did.
            if rst_count:
                star_result["rst_count"] = rst_count
            if answer_summary and answer_summary != "*":
                star_result["note"] = answer_summary
            self.result[hop - 1]["result"].append(star_result)
        else:
            packetlist = utils.convert_packetlist.packetlist2json(
                answered, unanswered, self.from_ip)
            hop_result = {
                "from": from_ip,
                "rtt": rtt,
                "size": size,
                "ttl": ttl,
                "summary": answer_summary,
                "rst_count": rst_count,
                "packets": packetlist,
            }
            # The path-level `port` is only the *starting* port once RST backoff
            # can rotate mid-trace, so record what this probe actually used.
            if dport is not None:
                hop_result["dport"] = dport
            self.result[hop - 1]["result"].append(hop_result)

    def set_endtime(self, endtime):
        self.endtime = endtime
        # `src_addr` is the *local* source address and `from_ip` the public one,
        # so on any NATted connection — which is every residential one, and
        # certainly every one behind CGNAT — they never matched and the scrub
        # never fired, so the local address survived in `src_addr` and in every
        # stored packet blob. It is not measurement data: `Tracer.send_packet`
        # overwrites `IP.src` on every probe.
        self.src_addr = '127.1.2.7'
        if self.from_ip != '127.1.2.7':
            self.from_ip = '127.1.2.7'

    def clean_extra_result(self):
        result_index = 0
        for try_step in self.result:  # will be up to 255
            results = try_step["result"]
            repeat_steps = 0
            for result in results:  # will be unknown
                if "x" in result.keys():
                    if '-' == result["x"]:
                        repeat_steps += 1
            if repeat_steps == len(results):
                del self.result[result_index:]
                break
            result_index += 1

    def json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          indent=4)
