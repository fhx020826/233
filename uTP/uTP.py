import struct
from peer.peer import bt_partion

"""
version 1 header:

0       4       8               16              24              32
+-------+-------+---------------+---------------+---------------+
| type  | ver   | extension     | connection_id                 |
+-------+-------+---------------+---------------+---------------+
| timestamp_microseconds                                        |
+---------------+---------------+---------------+---------------+
| timestamp_difference_microseconds                             |
+---------------+---------------+---------------+---------------+
| wnd_size                                                      |
+---------------+---------------+---------------+---------------+
| seq_nr                        | ack_nr                        |
+---------------+---------------+---------------+---------------+

如果extension字段非0
则该字段变化为
0               8               16
+---------------+---------------+
| extension     | len           |
+---------------+---------------+
len表示下一拓展字段的长度，不同的拓展字段有不同的类型，这里不再仔细分析

"""

def intnum(bynum:bytes):
    num =  int.from_bytes(bynum,byteorder='big',signed=False)
    return num
def utp_partion(data:bytes):
    try:
        utpdict = dict()
        utp = Utp.decode(data)
        utpdict = utp.utpdict
        utp_len = utp.utp_len
        #print(utpdict,utp_len)
        if utpdict:
            return utpdict,utp_len
        else:
            return None,0
    except Exception as e:
        #print(e)
        return None,0
    
        





class Utp:
    def __init__(self,utpdict:dict,utp_len:int):
        self.utpdict = utpdict
        self.utp_len = utp_len
    @classmethod
    def decode(cls,data:bytes):
        unpack_format = '>xbHIIIHH'
        utp_len = 20
        if data[1] == 0:#如果拓展字段为0
            parts = list(struct.unpack(unpack_format, data[:utp_len]))
            byte = hex(data[0])#'0x41' 注意'0x1'str 
            if len(byte) == 4:
                parts = [byte[2],byte[3]] +parts
            else:#注意'0x1'
                parts = ['0',byte[2]] +parts
            keys = ["Type","Version","Extension",'Connection Id',"Timestamp Microseconds","Timestamp Difference Microseconds","Window Size","Sequence Number","ACK Number"]
            utpdict = dict(zip(keys,parts))
        else:#不为0
            len_ext = data[2]
            format = format = '>xxx'+str(len_ext)+'sHIIIHH'
            utp_len+=1+len_ext
            parts = list(struct.unpack(format, data[:utp_len]))
            byte = hex(data[0])#'0x41' str
            if len(byte) == 4:
                parts = [byte[2],byte[3]] +parts
            else:#注意'0x1'
                parts = ['0',byte[2]] +parts
            parts = [byte[2],byte[3],hex(data[1]),len_ext] +parts
            keys = ["Type","Version","Extension","Length Of Extension","Expanded content",'Connection Id',"Timestamp Microseconds","Timestamp Difference Microseconds","Window Size","Sequence Number","ACK Number"]
        return cls(utpdict,utp_len)