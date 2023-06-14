from scapy.all import *
def intnum(bynum:bytes):
    num =  int.from_bytes(bynum,byteorder='big',signed=False)
    return num
def read_pcap(fp:str) -> scapy.plist.PacketList:
    package = rdpcap(fp)
    return package
def get_raw(package) -> bytes:
    if package.haslayer(Raw):
        raw = package.getlayer(Raw).load
        #print(raw)
        return raw
    return None