import aiohttp
import asyncio
from urllib.parse import urlencode
from util.myclass import torrent2hash
from util.logger import get_logger
from database.database import Database
import bencoder

from qbittorrent import Client

torrent = "D:\\c\\magnet-dht-master\\magnet_dht\pybt\\files\\OIP-C.jpg.torrent"
async def tracker_change(hashinfo:bytes,event = str.encode('completed'),tracker = 'http://172.20.138.184:8088/announce'):
    params = {
            'info_hash': hashinfo,
            #bytes.fromhex('8983286b122001c7ce13a455090a79370c5bf9e4'),
            'peer_id': str.encode('-qB1111-xyVnF6zGdBYu'),
            'port': 6889,
            'uploaded': 0,
            'downloaded': 1012,
            'left': 0,
            'compact': 1,
            'event' : event
            #'stopped'
            }
    timeout = aiohttp.ClientTimeout(total=101)
    url = tracker + '?' + urlencode(params)
    byte = bytes() 
    #connector = aiohttp.TCPConnector(local_addr = ('172.20.127.7',6889))
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url,proxy = '') as response:
            print(response)
            byte = await response.content.read()
    #print(byte)
    dictlist = bencoder.bdecode(byte)
    print(dictlist)

    

async def tracker_scrape(tracker) -> dict:
    timeout = aiohttp.ClientTimeout(total=101)
    url = tracker + 'scrape'
    byte = bytes() 
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as response:
            print(response)
            byte = await response.content.read()
    #print(byte)
    dictlist = bencoder.bdecode(byte)
    download = Download('D:\\c\\magnet-dht-master\\magnet_dht\\pybt\\tests')
    download.download(dictlist)

class Download:
    def __init__(self,dl_path):
        self.qb = Client('http://127.0.0.1:8080/', verify=False)
        self.qb.login()
        self.torrents = self.qb.torrents()
        self.dl_path = dl_path
        self.db = Database()
        self.logger = get_logger('D:\\c\\magnet-dht-master\\magnet_dht\\pybt\\log\\scrape.log')
        
    def download(self,dictlist:dict):
        #result = []
        for i in dictlist[b'files'].keys():
            infohash = i.hex()
            #bytes.decode()
            self.qb.download_from_link(infohash)
            self.logger.info(f'下载文件hash： {infohash}')
            self.db.add(infohash,)

            #self.qb.get_alternative_speed_status()
def start_scrape(tracker = 'http://127.0.0.1:8088/'):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tracker_scrape(tracker))
    loop.close()

def change():
    '''
    将文件载入tracker
    '''
    db = Database()
    result = db.get_allhash()
    db.close()
    #print(result[0][0])
    loop = asyncio.get_event_loop()
    for i in result:
        loop.run_until_complete(tracker_change(bytes.fromhex(i[0])))
    loop.close()



if __name__ == '__main__':
    change()
    #start_scrape('http://open.acgtracker.com:1096/')
    

