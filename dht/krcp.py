import bencoder

def krcp(data:bytes) -> dict:
    krcp = Krcp.decode(data)
    if krcp:
        return [krcp.krcp_dict]
    else:
        return None

class Krcp():
    def __init__(self,krcp_dict:dict):
        self.krcp_dict = krcp_dict
        
    @classmethod
    def decode(cls,data:bytes):
        try:
            result = bencoder.bdecode(data)
            result = dict(zip([bytes.decode(key) for key in result.keys()],result.values()))
            return cls(result)
        except Exception:
            return None

