#!/usr/bin/env python3
import base64
import json
import subprocess

from scapy.all import IP, TCP, UDP, Ether, hexdump, import_hexcap

import utils.anonymize

FIREWALL_COMMANDS_HELP = "\r\n( · - · · · \r\n\
You may need to temporarily block RST output packets in your firewall.\r\n\
For example with iptables the commands are:\r\n\
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP\r\n\
After the test, you can delete it:\r\n\
iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP\r\n · - · - · )\r\n"


class BADPacketException(Exception):
    """ An Exception which is thrown on bad packets """
    ...


class FirewallException(Exception):
    """ An Exception which is thrown on firewall errors """
    ...


class InputPacketInfo:
    def __init__(self, packet1, packet2, do_tcph1, do_tcph2, add_firewall_rule):
        self._packet1 = packet1
        self._packet2 = packet2
        self._do_tcph1 = do_tcph1
        self._do_tcph2 = do_tcph2
        self._add_firewall_rule = add_firewall_rule

    @staticmethod
    def _dump(packet):
        """Hexdump a packet with the operator's source address removed.

        This is the seam every dumped config passes through, and it is how LAN
        addresses reached `samples/`: nine committed samples carry a real
        `192.168.*` source because the JSON input path never applied the
        sentinel that `_read_pasted_packet` applies. Scrubbing here covers every
        input path at once.

        Behaviour-neutral — `Tracer.send_packet` overwrites `IP.src` on every
        probe, so the stored source is never what goes on the wire. The rebuild
        is what keeps the header checksum consistent with the new address.
        """
        copied = packet.copy()
        if copied.haslayer(IP):
            copied[IP].src = utils.anonymize.SENTINEL_SOURCE
            # Both layers: the TCP/UDP checksum covers an IP pseudo-header, so
            # the new source invalidates it as well. A header that does not
            # verify against its own address is a sharper fingerprint than the
            # address was — `samples/quicvd29.conf` shipped one for exactly this
            # reason before backlog §2.8.
            for layer in (IP, TCP, UDP):
                if copied.haslayer(layer):
                    del copied[layer].chksum
            copied = IP(bytes(copied))
        return 'b64:' + base64.b64encode(
            hexdump(copied, True).encode()).decode()

    def as_dict(self):
        res = {
            "packet1": {
                'hex': self._dump(self._packet1),
                'handshake': self._do_tcph1,
            },
        }
        if self._packet2:
            res['packet2'] = {
                'hex': self._dump(self._packet2),
                'handshake': self._do_tcph2,
            }
        res["add_firewall_drop"] = self._add_firewall_rule
        return res

    @property
    def params(self):
        return (self._packet1 or "", self._packet2 or "", self._do_tcph1, self._do_tcph2)

    def __enter__(self):
        if self._add_firewall_rule:
            self._add_firewal_out_drop_rule()
        return self.params

    def __exit__(self, *args, **kwargs):
        if self._add_firewall_rule:
            self._remove_firewal_out_drop_rule()

    @classmethod
    def _iptables_exists(cls):
        try:
            p = subprocess.run(['iptables', '-L', '-n'], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except:
            return False

    @classmethod
    def _check_firewal_out_drop_rule(cls):
        try:
            p = subprocess.run(['iptables', '-C', 'OUTPUT', '-p', 'tcp',
                                '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except:
            return False

    @classmethod
    def _add_firewal_out_drop_rule(cls):
        try:
            p = subprocess.run(['iptables', '-A', 'OUTPUT', '-p', 'tcp',
                                '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not cls._check_firewal_out_drop_rule():
                raise FirewallException("Added DROP rule cannot be verified")
            return True
        except:
            raise FirewallException("Adding DROP rule failed")

    @classmethod
    def _remove_firewal_out_drop_rule(cls):
        try:
            p = subprocess.run(['iptables', '-D', 'OUTPUT', '-p', 'tcp',
                                '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if cls._check_firewal_out_drop_rule():
                raise FirewallException(
                    "Removing DROP rule cannot be verified")
            return True
        except:
            raise FirewallException("Removing DROP rule failed")

    @classmethod
    def _ask_yesno(cls, question):
        prompt = f'{question} (y/n): '
        answer = input(prompt).strip().lower()
        if answer not in ['y', 'n']:
            print(f'{answer} is invalid, please try again...')
            return cls._ask_yesno(question)
        if answer == 'y':
            return True
        return False

    @classmethod
    def _supported_or_correct(cls, copied_packet):
        return (copied_packet.haslayer(IP) and (copied_packet[IP].version == 4))

    @classmethod
    def _read_pasted_packet(cls, show=False):
        print(" ********************************************************************** ")
        print(" paste here the packet hex dump start with the IP layer and then enter :")
        print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        packet_string = import_hexcap()
        print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        packet_object = None
        if not cls._supported_or_correct(IP(packet_string)):
            if not cls._supported_or_correct(Ether(packet_string).payload):
                raise BADPacketException(
                    "it's not IPv4 or the hexdump is not started with IP layer")
            else:
                packet_object = Ether(packet_string).payload
        else:
            packet_object = IP(packet_string)
        packet_object[IP].src = '127.1.2.7'
        if show:
            print(" . . . - . developed view of this packet:")
            packet_object.show()
            print(" . . . - .   (make sure it's correct)   . . . - . ")
        return packet_object

    @classmethod
    def from_stdin(cls, os_name: str, trace_retransmission: bool):
        copy_packet_1: 'scapy.layers.inet.Packet' = None
        copy_packet_2: 'scapy.layers.inet.Packet' = None
        do_tcph1: bool = False
        do_tcph2: bool = False
        add_firewall_rule = False
        copy_packet_1 = cls._read_pasted_packet(True)
        if not trace_retransmission:
            if copy_packet_1.haslayer(TCP) and copy_packet_1[TCP].flags == "PA":
                if os_name.lower() == "linux":
                    do_tcph1 = cls._ask_yesno(
                            f"Would you like to do a TCP Handshake before sending this packet?")
                    if not cls._check_firewal_out_drop_rule():
                        add_firewall_rule = cls._ask_yesno(
                            f"{FIREWALL_COMMANDS_HELP}\n\nDo You want add rules automaticallly using iptables?")
                        
                        if add_firewall_rule and not cls._iptables_exists():
                            # FIXME: WHAT IF NOT? FAIL?
                            raise FirewallException("iptables is not installed on this system, you may need use some other method to manually handle OS RST responses if there is such a problem!")
                else:
                    do_tcph1 = cls._ask_yesno(
                        "Would you like to do a TCP Handshake before sending this packet?")
                print(" · - · - ·     · - · - ·     · - · - ·     · - · - · ")

            if cls._ask_yesno("Would you like to add a second packet"):
                copy_packet_2 = cls._read_pasted_packet(True)
                if copy_packet_2.haslayer(TCP):
                    if copy_packet_2[TCP].flags == "PA":
                        do_tcph2 = cls._ask_yesno(
                            "Would you like to do a TCP Handshake before sending this packet?")
        print(" ********************************************************************** ")
        return InputPacketInfo(copy_packet_1, copy_packet_2, do_tcph1,  do_tcph2, add_firewall_rule)

    @classmethod
    def _read_json_packet(cls, json_config, k, show=False):
        if json_config[k]['hex'].startswith("b64:"):
            json_config[k]['hex'] = base64.b64decode(
                json_config[k]['hex'][4:].strip()).decode()
        packet = IP(import_hexcap(json_config[k]['hex']))
        print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        print(" . . . - . developed view of first packet:")
        if not cls._supported_or_correct(packet):
            raise BADPacketException(
                f"{k} it's not IPv4 or the hexdump is not started with IP layer")
        if show:
            packet.show()
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        return packet

    @classmethod
    def from_json(cls, os_name: str, trace_retransmission: bool, packet_data: json):
        copy_packet_1: 'scapy.layers.inet.Packet' = None
        copy_packet_2: 'scapy.layers.inet.Packet' = None
        do_tcph1: bool = False
        do_tcph2: bool = False
        add_firewall_rule = False
        try:
            json_config = packet_data
            copy_packet_1 = cls._read_json_packet(
                json_config, 'packet1', show=True)
            if not trace_retransmission:
                if copy_packet_1.haslayer(TCP):
                    if copy_packet_1[TCP].flags == "PA":
                        do_tcph1 = json_config['packet1'].get(
                            'handshake', False)
                if 'packet2' in json_config:
                    copy_packet_2 = cls._read_json_packet(
                        json_config, 'packet2', show=True)
                    if copy_packet_2.haslayer(TCP):
                        if copy_packet_2[TCP].flags == "PA":
                            do_tcph2 = json_config['packet2'].get(
                                'handshake', False)
            add_firewall_rule = json_config.get('add_firewall_drop', False)
            print(
                " ********************************************************************** ")
        except FileNotFoundError:
            print(f" · · · · · · · · file '{file}' not found!.")
            raise BADPacketException("File Not Found")
        return InputPacketInfo(copy_packet_1, copy_packet_2, do_tcph1,  do_tcph2, add_firewall_rule)

    @staticmethod
    def _interactive_namespace():
        """The names available at the interactive prompt.

        Everything scapy exports, so `IP(dst="1.1.1.1")/TCP()` works as typed.
        The namespace used to be this method's `locals()`, which held `cls`,
        `show` and the scapy *module* — so building a packet actually meant
        `scapy.all.IP(...)`, which is not what the banner asks for.
        """
        import scapy.all
        return dict(vars(scapy.all))

    @classmethod
    def _read_interactive_packet(cls, show=False):
        banner = "Please create your packet in variable \"p\" and exit when you are done"
        namespace = cls._interactive_namespace()
        try:
            from IPython.terminal.embed import InteractiveShellEmbed
        except ImportError:
            # IPython is a convenience, not a requirement (backlog §2.9): it is
            # not in requirements.txt and may well be absent in the restricted
            # environments this tool is aimed at. The stdlib console builds the
            # same packet. This fallback existed but sat *after* an
            # unconditional `raise`, so it was unreachable and anyone without
            # IPython was told "Currently Only IPython Console is supported!".
            print(" . . . - . IPython not found, using the built-in console."
                  " Press Ctrl-D when you are done.")
            import code
            code.interact(banner=banner, local=namespace)
        else:
            ipshell = InteractiveShellEmbed(banner1=banner, user_ns=namespace)
            ipshell()
            namespace = ipshell.user_ns
        # Leaving without assigning `p` used to surface as a bare `KeyError`
        # swallowed by the `except:` above and reported as IPython's absence.
        if "p" not in namespace:
            raise BADPacketException(
                "no packet found: assign the packet you built to `p` before"
                " leaving the console")
        packet = namespace["p"]
        if not hasattr(packet, "haslayer"):
            raise BADPacketException(
                f"`p` is a {type(packet).__name__}, not a scapy packet")
        if not cls._supported_or_correct(packet):
            raise BADPacketException(
                "it's not IPv4 or the hexdump is not started with IP layer")
        if show:
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
            print(" . . . - . developed view of first packet:")
            packet.show()
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        return packet

    @classmethod
    def from_scapy(cls, os_name: str, trace_retransmission: bool):
        copy_packet_1 = ""
        copy_packet_2 = ""
        do_tcph1 = False
        do_tcph2 = False
        add_firewall_rule = False
        copy_packet_1 = cls._read_interactive_packet(show=True)
        if not trace_retransmission:
            if os_name.lower() == "linux":
                do_tcph1 = cls._ask_yesno(
                    f"Would you like to do a TCP Handshake before sending this packet?")
                if not cls._check_firewal_out_drop_rule():
                    add_firewall_rule = cls._ask_yesno(
                        f"{FIREWALL_COMMANDS_HELP}\n\nDo You want add rules automaticallly using iptables?")
                if add_firewall_rule and  not cls._iptables_exists():
                    # FIXME: WHAT IF NOT? FAIL?
                    raise FirewallException("iptables is not installed on this system, you may need use some other method to manually handle OS RST responses if there is such a problem!")
            else:
                do_tcph1 = cls._ask_yesno(
                    "Would you like to do a TCP Handshake before sending this packet?")
            print(" · - · - ·     · - · - ·     · - · - ·     · - · - · ")
            if cls._ask_yesno("Would you like to add a second packet"):
                copy_packet_2 = cls._read_interactive_packet(show=True)
                if copy_packet_2.haslayer(TCP) and copy_packet_2[TCP].flags == "PA":
                    do_tcph2 = cls._ask_yesno(
                        "Would you like to do a TCP Handshake before sending this packet?")
        print(" ********************************************************************** ")
        return InputPacketInfo(copy_packet_1, copy_packet_2, do_tcph1,  do_tcph2, add_firewall_rule)
