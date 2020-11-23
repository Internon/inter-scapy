#!/usr/bin/python2

"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

import nfqueue
from scapy.all import *
import os

# All packets that should be filtered :
targetip = "10.11.2.213"
localip = "10.93.3.124"
srcport = 0 
shellport = 10443
attackport = 445
# If you want to use it as a reverse proxy for your machine
iptablesrout = "iptables -A OUTPUT --destination " + targetip + " -j NFQUEUE"
iptablesrin = "iptables -A INPUT --source " + targetip + " -j NFQUEUE"

# If you want to use it for MITM :
# iptablesr = "iptables -A FORWARD -j NFQUEUE"

print("Adding iptable rules :")
print(iptablesrout)
print(iptablesrin)
os.system(iptablesrout)
os.system(iptablesrin)
# If you want to use it for MITM attacks, set ip_forward=1 :
#print("Set ipv4 forward settings : ")
#os.system("sysctl net.ipv4.ip_forward=1")
class PacketModifier(object):
    def __init__(self):
        self.oldportout = {}
        self.oldportin = {} 

    def callback(self,payload):
        # Here is where the magic happens.
        data = payload.get_data()
        prt = IP(data)
        #prt = pkt/TCP(data)
        print("Got a packet ! source: " + str(prt[IP].src) + ":" + str(prt[TCP].sport) + " and dest: " + str(prt[IP].dst) + ":" + str(prt[TCP].dport) )
        if (prt[TCP].dport != shellport and prt[TCP].sport != shellport):
            if (prt[IP].src == targetip or prt[IP].src == localip):
                if (prt[IP].src == localip):
                    if (prt[TCP].sport in self.oldportin.keys()) and (prt[IP].src in self.oldportin[prt[TCP].sport].keys()):

                        #self.oldportout[prt.dport] = {prt[IP].dst:prt[TCP].sport}
                        #print("Changing source port " + str(prt[TCP].sport))
                        #prt2 = prt
                        #prt[TCP].sport = srcport
                        print("Changing dst port " + str(prt[TCP].dport))
                        prt[TCP].dport = self.oldportin[prt[TCP].sport][prt[IP].src]
                        print("Changed to " + str(prt[TCP].dport))
                    else:
                        self.oldportout[prt[TCP].dport] = {prt[IP].dst:prt[TCP].sport}
                        print("Changing source port " + str(prt[TCP].sport))
                        prt[TCP].sport = srcport
                        #prt[TCP].sport = self.oldportin[prt[TCP].dport][prt[IP].dst]
                        print("Changed to " + str(prt[TCP].sport))
                    del prt[IP].chksum
                    del prt[TCP].chksum
                    prt[IP].len = len(str(prt))
                    prt[TCP].len = len(str(prt[TCP]))
                    #prt2.show2()
                    #prt3 = IP(prt2.build())
                    #del prt2.chksum
                    #prt2 = prt2.__class__(bytes(prt2)
                
                    payload.set_verdict_modified(nfqueue.NF_ACCEPT,str(prt),len(prt))
                elif (prt[IP].src == targetip):
                
                    #prt2 = prt
                    if (prt[TCP].sport in self.oldportout.keys()) and (prt[IP].src in self.oldportout[prt[TCP].sport].keys()):
                        print("Changing dest port " + str(prt.dport))
                        prt[TCP].dport = self.oldportout[prt[TCP].sport][prt[IP].src]
                        print("Changed to " + str(prt[TCP].dport))
                    else:
                        print("Changing source port " + str(prt.sport))
                        self.oldportin[prt[TCP].dport] = {prt[IP].dst:prt[TCP].sport}
                        prt[TCP].sport = srcport
                        print("Changed to " + str(prt[TCP].sport))
                    del prt[IP].chksum
                    del prt[TCP].chksum
                    prt[IP].len = len(str(prt))
                    prt[TCP].len = len(str(prt[TCP])) #prt2.show2()
                    #prt3 = IP(prt2.build())
                    #del prt2.chksum
                    #prt2 = prt2.__class__(bytes(prt2))
                    payload.set_verdict_modified(nfqueue.NF_ACCEPT,str(prt),len(prt))
        else:
            payload.set_verdict(nfqueue.NF_ACCEPT)
    # If you want to modify the packet, copy and modify it with scapy then do :
    #payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))


def main():
    # This is the intercept
    q = nfqueue.queue()
    pkrmodifier = PacketModifier()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(pkrmodifier.callback)
    q.create_queue(0)
    try:
        q.try_run() # Main loop
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        print("Flushing iptables.")
        # This flushes everything, you might wanna be careful
        os.system('iptables -F')
        os.system('iptables -X')


if __name__ == "__main__":
    main()
