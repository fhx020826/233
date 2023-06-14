import asyncio
import socket
from util.myclass import Handshake,calculate_peer_id,BitField,Request,Piece,Interested,Unchoke
from util.logger import get_logger
from database.database import Database
#import random
HANDSHARK_LEN = 68
REQUEST_SIZE = 2**14
logfile = 'D:\c\magnet-dht-master\magnet_dht\pybt\log\server.log'
class Server:
    def __init__(self,port = 9090):
        self.port = port
        self.loop = asyncio.get_event_loop()
        self.logger = get_logger(logfile)
        self.db = Database()
    
    async def echo(self):


        my_peer_id = calculate_peer_id()
        self.logger.info(f'来自 {self.addr} 的连接......')
        data = await self.loop.sock_recv( self.sock, 1024)
        if data[0] == 19:#接收hanndshake
            handshake = Handshake.decode(data)
            info_hash = handshake.info_hash

            self.logger.info(f'收到来自 {handshake.peer_id.hex()} 的handshake消息： info_hash - {info_hash.hex()}')
            print(f'收到来自 {handshake.peer_id.hex()} 的handshake消息： info_hash - {info_hash.hex()}')
            #搜索数据库
            torrent,file,danger = self.db.check(info_hash.hex())
            if danger:
                self.logger.info(f'{handshake.peer_id.hex()} 请求非法文件!!!')
                print(f'{handshake.peer_id.hex()} 请求非法文件!!!')
            #发送handshake
            await self.loop.sock_sendall(self.sock, Handshake(info_hash,my_peer_id).encode())
            #await writer.drain()
            self.logger.info(f'向 {handshake.peer_id.hex()} 发送handshake消息')
            print(f'向 {handshake.peer_id.hex()} 发送handshake消息')
            #info_hash -> torrent, file_name
            #发送bitfield
            await self.loop.sock_sendall(self.sock, BitField(torrent).encode())
            #await writer.drain() 
            self.logger.info(f'向 {handshake.peer_id.hex()} 发送bitfield消息')
            print(f'向 {handshake.peer_id.hex()} 发送bitfield消息')

        else:
            self.sock.close()
            self.logger.info(f'连接不合法,断开与 {self.addr} 的连接')
            print(f'连接不合法,断开与 {self.addr} 的连接')
            return None
        #Interest
        data = await self.loop.sock_recv( self.sock, 1024)
        Interested.decode(data)
        self.logger.info(f'收到来自 {handshake.peer_id.hex()} 的interested消息')
        print(f'收到来自 {handshake.peer_id.hex()} 的interested消息')

        #unchock
        await self.loop.sock_sendall(self.sock, Unchoke().encode())
        self.logger.info(f'向 {handshake.peer_id.hex()} 发送unchock消息')
        #request piece
        while True:
            data = await self.loop.sock_recv( self.sock, 1024)
            try:
                request = Request.decode(data)
                self.logger.info(f'收到来自 {handshake.peer_id.hex()} 的request消息： index - {request.index}; begin - {request.begin}; length - {request.length}')
                print(f'收到来自 {handshake.peer_id.hex()} 的request消息： index - {request.index}; begin - {request.begin}; length - {request.length}')

                #piece
                with open(file,'rb') as f:
                    f.seek(request.index*REQUEST_SIZE+request.begin)
                    block = f.read(request.length)
                    #污染
                    if danger:
                        block = (block[0]-10).to_bytes(1,byteorder='big', signed=True) + block[1:]
                    await self.loop.sock_sendall(self.sock, Piece(request.index,request.begin,block).encode())
                    self.logger.info(f'向 {handshake.peer_id.hex()} 发送piece消息： index - {request.index}; begin - {request.begin}; length - {request.length}')
                    print(f'向 {handshake.peer_id.hex()} 发送piece消息： index - {request.index}; begin - {request.begin}; length - {request.length}')

                    await asyncio.sleep(2)
            except Exception as e:
                self.sock.close()
                self.logger.info(f'{self.addr}断开连接')
                print(f'断开与 {self.addr} 的连接')
                print("连接结束")
                return None
    
    async def start(self):
        print(f'server启动......')
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #设置端口可重用，不然服务器关闭后几分钟之后才会关闭绑定的端口
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ip_port = ('localhost', self.port)
        server_socket.bind(ip_port)
        server_socket.listen()
        while True:
            print('等待连接中......')
            self.sock,self.addr = await self.loop.sock_accept(server_socket)
            await self.echo()
    
    def close(self):
        self.sock.close()
        self.loop.close()



