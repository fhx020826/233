from util.packagepretreat import read_pcap, get_raw
from peer.peer import *
from dht.krcp import krcp
from uTP.uTP import utp_partion
from tracker.http_tracker import http_tracker
from tracker.udp_tracker import udp_tracker
from scapy.layers import http as h  # 该库将http也作为单独的一个数据包层：http层
import yaml
from scapy.all import *
from util.logger import get_logger

pcap_fp = "D:\\c\\magnet-dht-master\\pcap\\tcp_dht_bt_test.pcap"# TODO 数据包改为实时捕获

analizied_list = []  # 最后结果存储[dictlist,head]
segment_dict = dict()  # 报文块存储字典{key = (ip.src,ip.dst), value = segment}
segment = bytes()  # 报文块
head = [0]  # 数据包的起始头位置
flag = dict()  # 字典记录当前特定方向的头{key = (ip.src,ip.dst), value = head:int}




bt = []
num_tracker = 0
num_dht = 0
num_utp = 0
num_bt = 0
i = 0

"""
当扫描到request和piece时，
标记ip对为bt协议通讯，
记录当前tcp序列，
对乱序tcp包进行缓存，
在修正tcp序列时，以新包为准

"""

def tcp(data: bytes, i: int, segment_tuple: tuple) -> list:
    global num_bt
    if data:
        print('bt')
        if segment_tuple in segment_dict:  # 存在前缀截断
            data = segment_dict[segment_tuple]+data
            # if i == 1758:
            #     print(len(data),data.hex())
            # #del segment_dict[segment_tuple]
            dictlist, segment = bt_partion(data)
            
            head[i] = flag[segment_tuple]  # 当前端的头记录
            if dictlist:  # 如果多个截断拼接完成，删除该方向的头
                del flag[segment_tuple]
                del segment_dict[segment_tuple]
        else:
            dictlist, segment = bt_partion(data)
        if segment:
            segment_dict[segment_tuple] = segment
            # 定义头的位置
            if segment_tuple not in flag:
                flag[segment_tuple] = i  # 记录特定方向的头
                head[i] = i  # 记录头的位置
        # print(head[i])
        # print(dictlist)
        if dictlist or segment:
            num_bt+=1
            bt.append(i)
        return dictlist


"""
from scapy.layers import http as h#该库将http也作为单独的一个数据包层：http层

"""


def http(p):
    try:
        field = None
        if p.haslayer(h.HTTPRequest):
            field = p[h.HTTPRequest].fields
            data = bytes.decode(field['Path'])
            result = http_tracker(data, True)

        elif p.haslayer(h.HTTPResponse):
            field = p[h.HTTPResponse].fields
            data = get_raw(p)
            result = http_tracker(data, False)
        field['URI Query'] = result
        return field
    except Exception as e:
        # print(e)
        return None


def udp(data: bytes, i: int, segment_tuple) -> list:
    global num_dht
    global num_bt
    global num_utp
    if data:
        dictlist = []
        prodict = krcp(data)  # DHT分析
        print('dht')
        if prodict:
            print(prodict)
            num_dht +=1
            return prodict
        prodict, utp_len = utp_partion(data)  # utp分析
        if prodict:
            print('utp',prodict)

            dictlist.append(prodict)
            if prodict['Type'] == '0':
                num_bt +=1
                # print(prodict)
                print('bt')
                if i == 261:
                    print(data)
                    print(data[utp_len:])
                    print(len(data),utp_len)
                if segment_tuple in segment_dict:  # 存在前缀截断
                    data = segment_dict[segment_tuple]+data[utp_len:]
                    
                    #del segment_dict[segment_tuple]
                    dictlist_temp, segment = bt_partion(data)
                    head[i] = flag[segment_tuple]  # 当前端的头记录
                    if dictlist_temp:  # 如果多个截断拼接完成，删除该方向的头
                        del flag[segment_tuple]
                        del segment_dict[segment_tuple]
                else:
                    dictlist_temp, segment = bt_partion(data[utp_len:])
                if segment:
                    segment_dict[segment_tuple] = segment
                    # 定义头的位置
                    if segment_tuple not in flag:
                        flag[segment_tuple] = i  # 记录特定方向的头
                        head[i] = i  # 记录头的位置
                if dictlist_temp:
                    dictlist = dictlist + dictlist_temp
                if segment or dictlist:
                    num_bt+=1
            print(dictlist)
            num_utp +=1
            return dictlist
        else:
            return None
    return None


def analizy(package, i: int) -> list:
    global num_tracker
    head.append(-1)  # 当前包的头为自己，标记为-1
    result = http(package)
    print('http',result)
    if result:#tracker
        num_tracker += 1
        return [result]
    ip_layer = package.getlayer('IP')
    if not ip_layer:
        ip_layer = package.getlayer('IPv6')
    if not ip_layer:
        return None
    segment_tuple = (ip_layer.src, ip_layer.dst)
    data = get_raw(package)  # bytes数据
    if package.haslayer("UDP"):
        result = udp_tracker(data)
        print('udp_tracker', result)
        if result:
            num_tracker += 1
            return result
        result = udp(data, i, segment_tuple)
        print('udp',result)
    elif package.haslayer("TCP"):
        result = tcp(data, i, segment_tuple)
        print('tcp',result)
    return result


yaml_path = "D:\\c\\magnet-dht-master\\magnet_dht\\pybt\\tests\\data.yaml"#加数据库
f = open(yaml_path, 'w')

def callback(package):
    
    global i
    print(i)
    dictlist = analizy(package,i)
    print('head',head[i])
    result = list(({'num': i}, dictlist, {'head': head[i]}))
    i+=1
    yaml.dump(result, f)

def test():
    global i
    resultlsit = []
    pcap_fp = "D:\\c\\magnet-dht-master\\pcap\\test3.pcap"# TODO 数据包改为实时捕获
    packlist = read_pcap(pcap_fp)
    for p in packlist:
        i += 1
        print(i)
        dictlist = analizy(p, i)
        #print('dictlist',dictlist)
        result = list(({'num': i}, dictlist, {'head': head[i]}))
        print(head[i])
        resultlsit.append(result)
        # analizied_list.append(DataAnalizied(dictlist,head[i]))
        if i > 1000:
            break
    print(bt)
    print('num_bt:%d\nnum_dht:%d\nnum_tracker:%d\nnum_utp:%d\n' % (num_bt,num_dht,num_tracker,num_utp))
    yaml.dump(resultlsit, f)
    


if __name__ == "__main__":
    #test()
    sniff(prn = callback,count = 0, iface = 'WLAN')

