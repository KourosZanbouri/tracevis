#!/usr/bin/env python3

import sys


def show_ifaces():
    from scapy.all import IFACES
    print(IFACES)


def get_iface_object(name_or_index):
    from scapy.all import IFACES
    if name_or_index == "":
        print("please set a correct iface name or index number")
        show_ifaces()
        sys.exit(1)
    else:
        try:
            return IFACES.dev_from_index(int(name_or_index))
        except ValueError:
            pass
        # Backlog §3.4. A typo here used to escape as scapy's bare ValueError
        # traceback, raised from inside the handler above. Treat it like the
        # empty case: say so and list what does exist.
        try:
            return IFACES.dev_from_name(name_or_index)
        except ValueError:
            print(f"unknown network interface '{name_or_index}'; "
                  "set a correct iface name or index number")
            show_ifaces()
            sys.exit(1)
