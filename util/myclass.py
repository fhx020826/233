import struct
import logging
import random
import bencoder
import hashlib
import bitstring
REQUEST_SIZE = 2**14


def torrent2hash(torrent:str) -> bytes:
    data = open(torrent,'rb')
    data = data.read()
    datadict = bencoder.bdecode(data)
    info_dict = datadict[b'info']
    return hashlib.sha1(bencoder.bencode(info_dict)).digest()

def calculate_peer_id():
    """
    Calculate and return a unique Peer ID.

    The `peer id` is a 20 byte long identifier. This implementation use the
    Azureus style `-PC1000-<random-characters>`.

    Read more:
        https://wiki.theory.org/BitTorrentSpecification#peer_id
    """
    return str.encode('-PC0001-' + ''.join(
        [str(random.randint(0, 9)) for _ in range(12)]))

class BitField():
    """
    The BitField is a message with variable length where the payload is a
    bit array representing all the bits a peer have (1) or does not have (0).

    Message format:
        <len=0001+X><id=5><bitfield>
    """
    def __init__(self, torrent:str):
        data = open(torrent,'rb')
        data = data.read()
        datadict = bencoder.bdecode(data)
        num_piece = len(datadict[b'info'][b'pieces'])//20
        bits = '0b'+ ''.join(str(1) for _ in range(num_piece)) + ''.join(str(0) for _ in range((8 - num_piece%8)))
        self.bitfield = bitstring.BitArray(bits).bytes

    def encode(self) -> bytes:
        """
        Encodes this object instance to the raw bytes representing the entire
        message (ready to be transmitted).
        """
        bits_length = len(self.bitfield)
        return struct.pack('>Ib' + str(bits_length) + 's',
                           1 + bits_length,
                           5,
                           self.bitfield)

    @classmethod
    def decode(cls, data: bytes):
        message_length = struct.unpack('>I', data[:4])[0]
        logging.debug('Decoding BitField of length: {length}'.format(
            length=message_length))

        parts = struct.unpack('>Ib' + str(message_length - 1) + 's', data)
        return cls(parts[2])

    def __str__(self):
        return 'BitField'
    

class Piece():
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
    length = 9

    def __init__(self, index: int, begin: int, block: bytes):
        """
        Constructs the Piece message.

        :param index: The zero based piece index
        :param begin: The zero based offset within a piece
        :param block: The block data
        """
        self.index = index
        self.begin = begin
        self.block = block

    def encode(self):
        message_length = Piece.length + len(self.block)
        return struct.pack('>IbII' + str(len(self.block)) + 's',
                           message_length,
                           7,
                           self.index,
                           self.begin,
                           self.block)

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Piece of length: {length}'.format(
            length=len(data)))
        length = struct.unpack('>I', data[:4])[0]
        parts = struct.unpack('>IbII' + str(length - Piece.length) + 's',
                              data[:length+4])
        return cls(parts[2], parts[3], parts[4])

    def __str__(self):
        return 'Piece'

class Request():
    """
    The message used to request a block of a piece (i.e. a partial piece).

    The request size for each block is 2^14 bytes, except the final block
    that might be smaller (since not all pieces might be evenly divided by the
    request size).

    Message format:
        <len=0013><id=6><index><begin><length>
    """
    def __init__(self, index: int, begin: int, length: int = REQUEST_SIZE):
        """
        Constructs the Request message.

        :param index: The zero based piece index
        :param begin: The zero based offset within a piece
        :param length: The requested length of data (default 2^14)
        """
        self.index = index
        self.begin = begin
        self.length = length

    def encode(self):
        return struct.pack('>IbIII',
                           13,
                           6,
                           self.index,
                           self.begin,
                           self.length)

    @classmethod
    def decode(cls, data: bytes):
        logging.debug('Decoding Request of length: {length}'.format(
            length=len(data)))
        # Tuple with (message length, id, index, begin, length)
        parts = struct.unpack('>IbIII', data)
        return cls(parts[2], parts[3], parts[4])

    def __str__(self):
        return 'Request'

class Interested():
    """
    The interested message is fix length and has no payload other than the
    message identifiers. It is used to notify each other about interest in
    downloading pieces.

    Message format:
        <len=0001><id=2>
    """

    def encode(self) -> bytes:
        """
        Encodes this object instance to the raw bytes representing the entire
        message (ready to be transmitted).
        """
        return struct.pack('>Ib',
                           1,  # Message length
                           2)
    @classmethod
    def decode(self,data:bytes):
        logging.debug('Decoding Handshake of length: {length}'.format(
            length=len(data)))
        try:
            parts = struct.unpack('>Ib', data)
            return parts[1] == 2
        except:
            return None

    def __str__(self):
        return 'Interested'
class Unchoke():
    """
    Unchoking a peer enables that peer to start requesting pieces from the
    remote peer.

    Message format:
        <len=0001><id=1>
    """
    def encode(self):
        return struct.pack('>Ib',
                           1,
                           1
                           )

    def __str__(self):
        return 'Unchoke'

class Handshake():
    """
    The handshake message is the first message sent and then received from a
    remote peer.

    The messages is always 68 bytes long (for this version of BitTorrent
    protocol).

    Message format:
        <pstrlen><pstr><reserved><info_hash><peer_id>

    In version 1.0 of the BitTorrent protocol:
        pstrlen = 19
        pstr = "BitTorrent protocol".

    Thus length is:
        49 + len(pstr) = 68 bytes long.
    """
    length = 49 + 19

    def __init__(self, info_hash: bytes, peer_id: bytes):
        """
        Construct the handshake message

        :param info_hash: The SHA1 hash for the info dict
        :param peer_id: The unique peer id
        """
        if isinstance(info_hash, str):
            info_hash = info_hash.encode('utf-8')
        if isinstance(peer_id, str):
            peer_id = peer_id.encode('utf-8')
        self.info_hash = info_hash
        #print(self.info_hash,peer_id)
        self.peer_id = peer_id

    def encode(self) -> bytes:
        """
        Encodes this object instance to the raw bytes representing the entire
        message (ready to be transmitted).
        """
        return struct.pack(
            '>B19s8x20s20s',
            19,                         # Single byte (B)
            b'BitTorrent protocol',     # String 19s
                                        # Reserved 8x (pad byte, no value)
            self.info_hash,             # String 20s
            self.peer_id)               # String 20s

    @classmethod
    def decode(cls, data: bytes):
        """
        Decodes the given BitTorrent message into a handshake message, if not
        a valid message, None is returned.
        """
        logging.debug('Decoding Handshake of length: {length}'.format(
            length=len(data)))
        try:
            parts = struct.unpack('>B19s8x20s20s', data[:68])
            return cls(info_hash=parts[2], peer_id=parts[3])
        except:
            return None

    def __str__(self):
        return 'Handshake'
