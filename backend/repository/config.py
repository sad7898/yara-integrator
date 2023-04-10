from io import TextIOWrapper
import os
import sqlite3
from typing import IO
import datetime
class Repository:
    def __init__(self,conn):
        self.conn = conn
    def rowToJson(self,row):
        return {
            "ENV":row[0],
            "MOBSF_URL": row[1],
            "SHOULD_DECOMPILE":row[2],
            "SHOULD_USE_MOBSF":row[3],
            "MOBSF_API_KEY": row[4]
        }
    def get(self):
        curr  = self.conn.execute('SELECT ENV,MOBSF_URL,SHOULD_DECOMPILE,SHOULD_USE_MOBSF,MOBSF_API_KEY FROM Config LIMIT 1')
        rows = curr.fetchall()
        
        r = [self.rowToJson(row) for row in rows][0]
        return r
    
    
    def update(self, payload) -> bool:
        if ('MOBSF_API_KEY' in payload and payload['MOBSF_API_KEY'] is not None): 
            self.conn.execute('UPDATE Config SET SHOULD_DECOMPILE = ?, SHOULD_USE_MOBSF = ?, MOBSF_URL = ?, MOBSF_API_KEY = ? WHERE ENV = "production"',
                              (payload['SHOULD_DECOMPILE'],payload['SHOULD_USE_MOBSF'],payload['MOBSF_URL'],payload['MOBSF_API_KEY']))
        else:
            self.conn.execute('UPDATE Config SET SHOULD_DECOMPILE = ?, SHOULD_USE_MOBSF = ?, MOBSF_URL = ? WHERE ENV = "production"',
                              (payload['SHOULD_DECOMPILE'],payload['SHOULD_USE_MOBSF'],payload['MOBSF_URL'],))
        
        self.conn.commit()
        return True
