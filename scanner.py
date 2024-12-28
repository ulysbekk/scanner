from scapy.all import sr1, IP, ICMP
from pysnmp.hlapi import *
import threading
import socket

def resolve_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        try:
            hostname = socket.gethostbyname(ip)
            return hostname
        except:
            return None

def icmp_scan(ip):
    packet = IP(dst=ip)/ICMP()
    response = sr1(packet, timeout=1, verbose=0)
    if response:
        hostname = resolve_hostname(ip)
        if hostname:
            print(f"{ip} is active = Hostname: {hostname}")
        else:
            print(f"{ip} is not responding - Hostname: Unresolved")
    else:
        print(f"{ip} is not responding")

for i in range(1, 256):
    ip = f"10.0.0.{i}"
    icmp_scan(ip)

def snmp_scan(ip, community='private'):
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        udpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        print(f"{ip}: {errorIndication}")
    elif errorStatus:
        print(f"{ip}: {errorStatus.prettyPrint()}")
    else:
        hostname = resolve_hostname(ip)
        if hostname:
            print(f"{ip}: SNMP response received - Hostname: {hostname}")
        else:
            print(f"{ip}: SNMP response received - Hostname: Null")
def threaded_scan(start, end):
    for i in range(start, end):
        ip = f"10.0.0.{i}"
        icmp_scan(ip)

threads = []
for i in range(1, 256, 50):
    t = threading.Thread(target=threaded_scan, args=(i, 9+50))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

