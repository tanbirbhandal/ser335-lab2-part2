from scapy.all import *

def reply(pkt):
    a=IP()
    a.src = pkt[IP].dst
    a.dst = pkt[IP].src
    b = ICMP()
    b.type = 0
    b.id = pkt[ICMP].id
    b.seq = pkt[ICMP].seq
    p = a/b/pkt[Raw].load
    send(p)

pkt = sniff(iface='br-fbd3896785e2', filter='icmp and icmp[icmptype] == 8', prn=reply)