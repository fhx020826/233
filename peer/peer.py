import logging
import struct
import bitstring
import bencoder
from util.packagepretreat import intnum
REQUEST_SIZE = 2**14
HANDSHARK_LEN = 68


def bt_partion(data:bytes):
    """
    Param:   data:bytes
    Return:  list(bytes)
    切割数据包,并根据特征数分类
    """
    datalist = []
    segment = bytes()
    length=0
    head = 0
    #print(data[0])
    if data[0] == 19:
        bt = Handshake.decode(data[:HANDSHARK_LEN])
        if bt:
            head = HANDSHARK_LEN
            datalist.append(bt.btdict)
    while head<len(data)-1:
        if intnum(data[head:head+2]) != 0:#根据数据包的前两位是否为0，来判断是否是长度，如果不是，说明该包一定不是bt数据包
            #segment
            return None,None
        length = intnum(data[head:head+4])
        print(length)
        if length == 0:
            return None,None
        tail = head+4+length
        if tail >len(data):#如果出现爆表，则说明存在segment
            segment = data[head:]
            return datalist,segment
        data_temp = data[head:tail]
        flag = data_temp[4]
        if length == 0:
            bt = KeepAlive.decode(data_temp)
        elif flag == (0 or 1):
            bt = Choke.decode(data_temp)
        elif flag == (2 or 3):
            bt = Interested.decode(data_temp)
        elif flag == 4:
            bt = Have.decode(data_temp)
        elif flag == 5:
            bt = BitField.decode(data_temp)
        elif flag == 6:
            bt = Request.decode(data_temp)
        elif flag == 7:
            bt = Piece.decode(data_temp)
            #print(len(bt.btdict['Data in a piece']))
        elif flag == 8:  
            bt = Cancel.decode(data_temp)
        elif flag == 9:
            bt = Port.decode(data_temp)
        elif flag == 13:
            bt = SuggestPice.decode(data_temp)
        elif flag == 14:
            bt = HaveAll.decode(data_temp)
        elif flag == 15:
            bt = HaveNone.decode(data_temp)
        elif flag == 16:
            bt = RejectRequest.decode(data_temp)              
        elif flag == 17:
            bt = AllowFast.decode(data_temp)
        elif flag == 20:
            bt = Extended.decode(data_temp)
        else:
            return None,None
        datalist.append(bt.btdict)
        head = tail
    #print(datalist)
    return datalist,segment

class PeerMessage:
    """
    A message between two peers.

    All of the remaining messages in the protocol take the form of:
        <length prefix><message ID><payload>

    - The length prefix is a four byte big-endian value.
    - The message ID is a single decimal byte.
    - The payload is message dependent.

    NOTE: The Handshake messageis different in layout compared to the other
          messages.

    Read more:
        https://wiki.theory.org/BitTorrentSpecification#Messages

    BitTorrent uses Big-Endian (Network Byte Order) for all messages, this is
    declared as the first character being '>' in all pack / unpack calls to the
    Python's `struct` module.
    """
    Choke = 0
    Unchoke = 1
    Interested = 2
    NotInterested = 3
    Have = 4
    BitField = 5
    Request = 6
    Piece = 7
    Cancel = 8
    Port = 9
    Handshake = None  # Handshake is not really part of the messages
    KeepAlive = None  # Keep-alive has no ID according to spec
    Extended = 20

    def encode(self) -> bytes:
        """
        Encodes this object instance to the raw bytes representing the entire
        message (ready to be transmitted).
        """
        pass

    @classmethod
    def decode(cls, data: bytes):
        """
        Decodes the given BitTorrent message into a instance for the
        implementing type.
        """
        pass


class Handshake(PeerMessage):
    """
   解析Handshake

    Message format:
        <pstrlen><pstr><reserved><info_hash><peer_id>

    In version 1.0 of the BitTorrent protocol:
        pstrlen = 19
        pstr = "BitTorrent protocol".

    Thus length is:
        49 + len(pstr) = 68 bytes long.
    """
    length = 49 + 19

    def __init__(self,btdict:dict):
        self.btdict = btdict

    @classmethod
    def decode(cls, data: bytes):
        """
        Decodes the given BitTorrent message into a handshake message, if not
        a valid message, None is returned.
        """
        logging.debug('Decoding Handshake of length: {length}'.format(
            length=len(data)))
        if len(data) < (49 + 19):
            return None
        parts = struct.unpack('>B19s8x20s20s', data)
        if parts[0] == 19 and parts[1] == b'BitTorrent protocol':
            keys = ["Protocol Name Length","Protocol Name","Reserved","dictionary hash","Peer ID"]
            btdict = dict(zip(keys,parts))
            return cls(btdict)
    def __str__(self):
        return 'Handshake'


class KeepAlive(PeerMessage):
    """
    The Keep-Alive message has no payload and length is set to zero.

    Message format:
        <len=0000>
    """
    def __str__(self):
        return 'KeepAlive'


class BitField(PeerMessage):
    """
    The BitField is a message with variable length where the payload is a
    bit array representing all the bits a peer have (1) or does not have (0).

    Message format:
        <len=0001+X><id=5><bitfield>
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict

    @classmethod
    def decode(cls, data: bytes):
        message_length = struct.unpack('>I', data[:4])[0]
        logging.debug('Decoding BitField of length: {length}'.format(
            length=len(data)))
        parts = struct.unpack('>Ib' + str(message_length - 1) + 's', data)
        keys = ["Message Length","Message Type","Bitfield data"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)

    def __str__(self):
        return 'BitField'


class Interested(PeerMessage):
    """
    The interested message is fix length and has no payload other than the
    message identifiers. It is used to notify each other about interest in
    downloading pieces.

    Message format:
        <len=0001><id=2>
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict

    def encode(self) -> bytes:
        """
        Encodes this object instance to the raw bytes representing the entire
        message (ready to be transmitted).
        """
        return struct.pack('>Ib',
                           1,  # Message length
                           PeerMessage.Interested)
    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Interested of length: {length}'.format(
            length=len(data)))
        parts = struct.unpack('>Ib', data)
        keys = ["Message Length","Message Type"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)

    def __str__(self):
        return 'Interested'


class NotInterested(PeerMessage):
    """
    The not interested message is fix length and has no payload other than the
    message identifier. It is used to notify each other that there is no
    interest to download pieces.

    Message format:
        <len=0001><id=3>
    """
    def __str__(self):
        return 'NotInterested'
    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding NotInterested of length: {length}'.format(
            length=len(data)))
        parts = struct.unpack('>Ib', data)
        keys = ["Message Length","Message Type"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)


class Choke(PeerMessage):
    """
    The choke message is used to tell the other peer to stop send request
    messages until unchoked.

    Message format:
        <len=0001><id=0>
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict
    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Choke of length: {length}'.format(
            length=len(data)))
        parts = struct.unpack('>Ib', data)
        keys = ["Message Length","Message Type"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)
    

    def __str__(self):
        return 'Choke'


class Unchoke(PeerMessage):
    """
    Unchoking a peer enables that peer to start requesting pieces from the
    remote peer.

    Message format:
        <len=0001><id=1>
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict
    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Choke of length: {length}'.format(
            length=len(data)))
        parts = struct.unpack('>Ib', data)
        keys = ["Message Length","Message Type"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)
    
    def __str__(self):
        return 'Unchoke'


class AllowFast(PeerMessage):
    """
    Represents a piece successfully downloaded by the remote peer. The piece
    is a zero based index of the torrents pieces
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict


    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Have of length: {length}'.format(
            length=len(data)))
        parts = list(struct.unpack('>Ib4s', data))
        keys = ["Message Length","Message Type","Piece index"]
        parts[2] = bytes(parts[2])
        btdict = dict(zip(keys,parts))
        return cls(btdict)

    def __str__(self):
        return 'AllowFast'
    
class SuggestPice(PeerMessage):
    """
    Represents a piece successfully downloaded by the remote peer. The piece
    is a zero based index of the torrents pieces
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict


    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Have of length: {length}'.format(
            length=len(data)))
        parts = list(struct.unpack('>Ib4s', data))
        keys = ["Message Length","Message Type","Piece index"]
        parts[2] = bytes(parts[2])
        btdict = dict(zip(keys,parts))
        return cls(btdict)

    def __str__(self):
        return 'SuggestPice'


class HaveAll(PeerMessage):
    """
    Represents a piece successfully downloaded by the remote peer. The piece
    is a zero based index of the torrents pieces
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict


    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Have of length: {length}'.format(
            length=len(data)))
        parts = list(struct.unpack('>Ib', data))
        keys = ["Message Length","Message Type"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)

    def __str__(self):
        return 'HaveAll'
class HaveNone(PeerMessage):
    """
    Represents a piece successfully downloaded by the remote peer. The piece
    is a zero based index of the torrents pieces
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict


    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Have of length: {length}'.format(
            length=len(data)))
        parts = list(struct.unpack('>Ib', data))
        keys = ["Message Length","Message Type"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)

    def __str__(self):
        return 'HaveNone'
    
class Have(PeerMessage):
    """
    Represents a piece successfully downloaded by the remote peer. The piece
    is a zero based index of the torrents pieces
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict


    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Have of length: {length}'.format(
            length=len(data)))
        parts = list(struct.unpack('>Ib4s', data))
        parts[2] = bytes(parts[2])
        keys = ["Message Length","Message Type","Piece index"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)

    def __str__(self):
        return 'Have'

class Port(PeerMessage):
    """
    解析port报文
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Have of length: {length}'.format(
            length=len(data)))
        parts = struct.unpack('>IbH', data)
        keys = ["Message Length","Message Type","Port"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)


class Request(PeerMessage):
    """
    The message used to request a block of a piece (i.e. a partial piece).

    The request size for each block is 2^14 bytes, except the final block
    that might be smaller (since not all pieces might be evenly divided by the
    request size).

    Message format:
        <len=0013><id=6><index><begin><length>
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Request of length: {length}'.format(
            length=len(data)))
        # Tuple with (message length, id, index, begin, length)
        parts = list(struct.unpack('>Ib4sII', data))
        keys = ["Message Length","Message Type","Piece index","Begin offset","Piece Length"]
        parts[2] = bytes(parts[2])
        btdict = dict(zip(keys,parts))
        return cls(btdict)

    def __str__(self):
        return 'Request'
class RejectRequest(PeerMessage):
    """
    The message used to request a block of a piece (i.e. a partial piece).

    The request size for each block is 2^14 bytes, except the final block
    that might be smaller (since not all pieces might be evenly divided by the
    request size).

    Message format:
        <len=0013><id=6><index><begin><length>
    """
    def __init__(self, btdict:dict):
        self.btdict = btdict

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Request of length: {length}'.format(
            length=len(data)))
        # Tuple with (message length, id, index, begin, length)
        parts = list(struct.unpack('>Ib4sII', data))
        keys = ["Message Length","Message Type","Piece index","Begin offset","Piece Length"]
        parts[2] = bytes(parts[2])
        btdict = dict(zip(keys,parts))
        return cls(btdict)

    def __str__(self):
        return 'RejectRequest'


class Piece(PeerMessage):
    """
    A block is a part of a piece mentioned in the meta-info. The official
    specification refer to them as pieces as well - which is quite confusing
    the unofficial specification refers to them as blocks however.

    So this class is named `Piece` to match the message in the specification
    but really, it represents a `Block` (which is non-existent in the spec).

    Message format:
        <length prefix><message ID><index><begin><block>
    """
    # The Piece message length without the block data
    def __init__(self, btdict:dict):
        self.btdict = btdict

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Piece of length: {length}'.format(
            length=len(data)))
        length = struct.unpack('>I', data[:4])[0]
        parts = list(struct.unpack('>Ib4sI' + str(length - 9) + 's',data) )
        keys = ["Message Length","Message Type","Piece index","Begin offset","Data in a piece"]
        parts[2] = bytes(parts[2])
        btdict = dict(zip(keys,parts))
        return cls(btdict)  
    def __str__(self):
        return 'Piece'


class Cancel(PeerMessage):
    """
    The cancel message is used to cancel a previously requested block (in fact
    the message is identical (besides from the id) to the Request message).

    Message format:
         <len=0013><id=8><index><begin><length>
    """
    def __init__(self, index, begin, length: int = REQUEST_SIZE):
        self.index = index
        self.begin = begin
        self.length = length

    def encode(self):
        return struct.pack('>IbIII',
                           13,
                           PeerMessage.Cancel,
                           self.index,
                           self.begin,
                           self.length)

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Cancel of length: {length}'.format(
            length=len(data)))
        # Tuple with (message length, id, index, begin, length)
        parts = struct.unpack('>IbIII', data)
        keys = ["Message Length","Message Type","Piece index","Begin offset","Piece Length"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)  

    def __str__(self):
        return 'Cancel'
    
class Extended(PeerMessage):
    def __init__(self,exdict:dict):
        self.btdict = exdict
    @classmethod 
    def decode(cls,data:bytes):
        message_length = struct.unpack('>I', data[:4])[0]
        logging.debug('Decoding Extended of length: {length}'.format(
            length=message_length))
        parts = list(struct.unpack('>Ibb', data[:6]))
        try:
            result = bencoder.bdecode(data[6:])
            result = dict(zip([bytes.decode(key) for key in result.keys()],result.values()))
            parts.append(result)
        except Exception:
            parts = list(struct.unpack('>Ibb'+str(parts[0]-2)+'s', data))
        
        keys = ["Message Length","Message Type","Extended ID","Dictonary"]
        btdict = dict(zip(keys,parts))
        return cls(btdict)  
        

