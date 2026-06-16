from scapy.all import *
from scapy.layers.l2 import STP
import time


def send_arp():
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        pdst="192.168.1.1"
    )

    send(pkt, verbose=False)
    print("[+] ARP")


def send_bgp():
    pkt = (
        IP(
            src="10.0.0.1",
            dst="10.0.0.2"
        )
        / TCP(
            sport=50000,
            dport=179
        )
    )

    send(pkt, verbose=False)
    print("[+] BGP")


def send_stp():
    pkt = (
        Ether(
            dst="01:80:c2:00:00:00"
        )
        / LLC()
        / STP()
    )

    sendp(pkt, verbose=False)
    print("[+] STP")


def send_lldp():
    pkt = (
        Ether(
            dst="01:80:c2:00:00:0e",
            type=0x88CC,
        )
        / Raw(b"LLDP_TEST")
    )

    sendp(pkt, verbose=False)
    print("[+] LLDP")


if __name__ == "__main__":

    while True:

        send_arp()
        time.sleep(1)

        send_bgp()
        time.sleep(1)

        send_stp()
        time.sleep(1)

        send_lldp()
        time.sleep(3)

