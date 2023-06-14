import struct
import logging
from socket import inet_ntoa
from util.packagepretreat import intnum
LEN_REQUEST_HEAD =8
LEN_ACTION = 4
PROTOCOL_ID = b"\x00\x00\x04\x17'\x10\x19\x80" #0x41727101980 // magic constant
def udp_tracker(data:bytes):
    try:
        if data[:LEN_REQUEST_HEAD] == PROTOCOL_ID:
            cls = ConRequest.decode(data)
        elif intnum(data[:LEN_ACTION]) == 0:
            cls = ConResponse.decode(data)
        elif intnum(data[LEN_REQUEST_HEAD:LEN_REQUEST_HEAD+LEN_ACTION]) == 1:
            cls = AnnRequeset.decode(data)
        elif intnum(data[:LEN_ACTION]) == 1:
            cls = AnnResponse.decode(data)
        elif intnum(data[LEN_REQUEST_HEAD:LEN_REQUEST_HEAD+LEN_ACTION]) == 2:
            cls = ScrapeRequeset.decode(data)
        elif intnum(data[:LEN_ACTION]) == 2:
            cls = ScrapeResponse.decode(data)
        elif intnum(data[:LEN_ACTION]) == 3:
            cls = Error.decode(data)
        else:
            return None
        return [cls.trdict]
    except Exception as e:
        #print(e)
        return None
    




class ConRequest():
    """
    Offset  Size            Name            Value
0       64-bit integer  protocol_id     0x41727101980 // magic constant
8       32-bit integer  action          0 // connect
12      32-bit integer  transaction_id
16
    """
    def __init__(self, trdict:dict):
        self.trdict = trdict

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Connect Request of length: {length}'.format(
            length=len(data)))
        parts = struct.unpack('>8sII', data)
        #print(parts)
        keys = ["Protocol Id","Action","Transaction Id"]
        trdict = dict(zip(keys,parts))
        return cls(trdict)

    def __str__(self):
        return 'Connect Request'
    
class ConResponse():
    """
    Offset  Size            Name            Value
    0       32-bit integer  action          0 // connect
    4       32-bit integer  transaction_id
    8       64-bit integer  connection_id
    16
    """
    def __init__(self, trdict:dict):
        self.trdict = trdict

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Connect Request of length: {length}'.format(
            length=len(data)))
        parts = struct.unpack('>IIQ', data)
        keys = ["Action","Transaction Id","Connection Id"]
        trdict = dict(zip(keys,parts))
        return cls(trdict)

    def __str__(self):
        return 'Connect Response'


class AnnRequeset():
    """
    Offset  Size    Name    Value
0       64-bit integer  connection_id
8       32-bit integer  action          1 // announce
12      32-bit integer  transaction_id
16      20-byte string  info_hash
36      20-byte string  peer_id
56      64-bit integer  downloaded
64      64-bit integer  left
72      64-bit integer  uploaded
80      32-bit integer  event           0 // 0: none; 1: completed; 2: started; 3: stopped
84      32-bit integer  IP address      0 // default
88      32-bit integer  key
92      32-bit integer  num_want        -1 // default
96      16-bit integer  port
98
    """
    def __init__(self, trdict:dict):
        self.trdict = trdict

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Announce Requeset of length: {length}'.format(
            length=len(data)))
        parts = struct.unpack('>QII20s20sQQQIIIIH', data[:98])
        keys = ["Connection Id","Action","Transaction Id","Info Hash","Peer Id","Downloaded","Left","Uploaded","Event","Ip Address","Key","Num Want","Port"]
        trdict = dict(zip(keys,parts))
        trdict["Ip Address"] = inet_ntoa(struct.pack(">I",trdict["Ip Address"]))#int -> str ip
        return cls(trdict)

    def __str__(self):
        return 'Announce Requeset'

class AnnResponse():
    """
    Offset      Size            Name            Value
0           32-bit integer  action          1 // announce
4           32-bit integer  transaction_id
8           32-bit integer  interval
12          32-bit integer  leechers
16          32-bit integer  seeders
20 + 6 * n  32-bit integer  IP address
24 + 6 * n  16-bit integer  TCP port
20 + 6 * N
    """
    def __init__(self, trdict:dict):
        self.trdict = trdict

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Announce Response of length: {length}'.format(
            length=len(data)))
        parts = list(struct.unpack('>IIIII', data[:20]))
        tail = 20
        addresslist = []#dictlist
        while tail < len(data-1):
            ip = inet_ntoa(data[tail+4])
            port = struct.unpack('>H', data[tail+4:tail+6])
            addresslist.append({'Ip Address':ip,"TCP port":port})
            tail += 6
        parts.append(addresslist)
        keys = ["Action","Transaction Id","Interval","Leechers","Seeders","Peers Address"]
        trdict = dict(zip(keys,parts))
        return cls(trdict)

    def __str__(self):
        return 'Announce Response'

class ScrapeRequeset():
    """
   Offset          Size            Name            Value
0               64-bit integer  connection_id
8               32-bit integer  action          2 // scrape
12              32-bit integer  transaction_id
16 + 20 * n     20-byte string  info_hash
16 + 20 * N
    """
    def __init__(self, trdict:dict):
        self.trdict = trdict

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Scrape Requeset of length: {length}'.format(
            length=len(data)))
        parts = struct.unpack('>QII', data[:16])
        tail = 16
        addresslist = []#dictlist
        while tail < len(data-1):
            infohash = struct.unpack('>20s', data[tail:tail+20])
            addresslist.append({'Info Hash':infohash})
            tail += 20
        keys = ["Connection Id","Action","Transaction Id","Info Hash List"]
        trdict = dict(zip(keys,parts))
        return cls(trdict)

    def __str__(self):
        return 'Scrape Requeset'


class ScrapeResponse():
    """
0           32-bit integer  action          2 // scrape
4           32-bit integer  transaction_id
8 + 12 * n  32-bit integer  seeders
12 + 12 * n 32-bit integer  completed
16 + 12 * n 32-bit integer  leechers
8 + 12 * N
    """
    def __init__(self, trdict:dict):
        self.trdict = trdict

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Scrape Response of length: {length}'.format(
            length=len(data)))
        parts = list(struct.unpack('>QII', data[:16]))
        tail = 8
        infolist = []#dictlist
        while tail < len(data-1):
            info = struct.unpack('>III', data[tail:tail+12])
            infokeys = ['Seeders','Completed','Leechers']
            infolist.append(dict(zip(infokeys,info)))
            tail += 12
        parts.append(infolist)
        keys = ["Action","Transaction Id","Info List"]
        trdict = dict(zip(keys,parts))
        return cls(trdict)

    def __str__(self):
        return 'Scrape Response'
class Error:
    def __init__(self, trdict:dict):
        self.trdict = trdict
    def decode(cls,data:bytes):
        logging.debug('Decoding Response Error of length: {length}'.format(
            length=len(data)))
        parts = list(struct.unpack('>II', data[:8]))
        parts.append(bytes.decode(data[8:]))
        keys = ["Action","Transaction Id","Message"]
        trdict = dict(zip(keys,parts))
        return cls(trdict)

    def __str__(self):
        return 'Response Error'
