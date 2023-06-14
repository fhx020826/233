import mysql.connector
from mysql.connector import Error
from util.logger import get_logger
from util.myclass import torrent2hash
class Database:
    def __init__(self):
        self.conn = mysql.connector.connect(
            host="localhost", 
            port=3306,
            user='root',    #在这里输入用户名
            password='zy123%.',  
            database='bt',
            charset='utf8' 
            )
        self.logger = get_logger('D:\\c\\magnet-dht-master\\magnet_dht\\pybt\\log\\database.log')
    def add(self,info_hash:str,torrent:str,file:str,danger:bool):
        # 打开数据库可能会有风险，所以添加异常捕捉
        try:
            cursor = self.conn.cursor()
            sql = f'insert into hash2file values("{info_hash}","{torrent}","{file}",{str(danger)});'
            cursor.execute(sql)
            self.conn.commit()
            self.logger.info(f'元组写入数据库 - ("{info_hash}","{torrent}","{file}",{str(danger)})')
        except Exception as e:
            self.conn.rollback()
            self.conn.close()

    def check(self,info_hash:str) -> tuple:
        # 打开数据库可能会有风险，所以添加异常捕捉
        try:
            cursor = self.conn.cursor()
            sql = f'select torrent,file,danger from hash2file where infohash = "{info_hash}";'
            cursor.execute(sql)
            data = cursor.fetchone()
            self.logger.info(f'查看数据库 - ("{info_hash}")')
            return data
        except Exception as e:
            #self.conn.rollback()
            self.conn.close()
            self.logger.error(f"数据库操作异常：{e}")
    def get_allhash(self) -> list:
        try:
            cursor = self.conn.cursor()
            sql = f'select infohash from hash2file;'
            cursor.execute(sql)
            data = cursor.fetchall()
            self.logger.info(f'获取数据库所有 infohash')
            return data
        except Exception as e:
            #self.conn.rollback()
            self.conn.close()
            self.logger.error(f"数据库操作异常：{e}")
    def close(self):
        self.conn.close()

def torrent_file_add2db(filename:str,danger:bool):
    db = Database()
    info_hash = torrent2hash(filename+'.torrent').hex()
    db.add(info_hash,filename+'.torrent',filename,danger)



        
