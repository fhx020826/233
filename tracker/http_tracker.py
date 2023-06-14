from urllib.parse import parse_qs
import bencoder


def http_tracker(data,isrequest:bool) ->dict:
    '''
    data:str | bytes
    '''

    if isrequest:
        '''
        data:str
        示例
        /announce?info_hash=%b2%90%bb%97uN%14%ff%14%9d%c4%e8%ce%cb%c6%b9%11%ea%90%c8&peer_id=-qB4520-xyVnF7zGdBYu&port=64773&uploaded=0&downloaded=0&left=1364213657&corrupt=0&key=50A29108&event=started&numwant=200&compact=1&no_peer_id=1&supportcrypto=1&redundant=0
        '''
        result = parse_qs(data)#解析uri的每一个字段
        '''
        result:dict 
        示例
        {key:str = '/announce?info_hash',value:list =[字符串格式的%b2%90%bb%97uN%14%ff%14%9d%c4%e8%ce%cb%c6%b9%11%ea%90%c8] }

        '''
        result = dict(zip(result.keys(),sum(result.values(),[])))
        result['info_hash'] = str.encode(result.pop('/announce?info_hash'))
    else:
        result = bencoder.bdecode(data)
        #bdecode解码出的键是bytes格式，转换为str
        result = dict(zip([bytes.decode(key) for key in result.keys()],result.values()))
    return result
