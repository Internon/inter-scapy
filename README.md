# inter-scapy
Change source port and/or destination port of trafic generated

This script might need some changes like process arguments (IPS and ports) and some changes it might need to solve possible issues

That worked for me on a pentest and i don't followed working on this, because the issue was that firewall (In this case fortinet) by default was blocking source port 1-65535 and if i make the requests using port 0 it bypased it.
