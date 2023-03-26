from io import TextIOWrapper
import os
import sqlite3
from typing import IO
from db.db import get_db
import datetime
RULE_DIRECTORY = "rules"
class Repository:
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Repository, cls).__new__(cls)
        return cls.instance
    def __init__(self):
        self.conn = get_db()
    def rowToJson(self,row):
        return {
            "id": row[0],
            "name":row[1],
            "updated":row[2],
            "description":row[3],
        }
    def insert(self,name:str,description: str,stream: IO):
        curr = self.conn.execute("INSERT INTO rules(name,description,updated) VALUES (?,?,?)",(name,description,datetime.datetime.now(),))
        self.conn.commit()
        fullPath = os.path.join("rules",str(curr.lastrowid))
        file = open(fullPath,"wb")
        lines = stream.readlines()
        for line in lines:
            file.write(line)

        return True

    def list(self):
        curr  = self.conn.execute('SELECT * FROM rules')
        rows = curr.fetchall()
        r = [self.rowToJson(row) for row in rows]
        return r
    
    def searchById(self,id) -> dict | None:
        row = self.conn.execute('SELECT * FROM rules WHERE id = ?',(id,)).fetchone()
        return self.rowToJson(row) if row is not None else row
    
    def searchByName(self,name="") -> dict | None:
        row = self.conn.execute('SELECT * FROM rules WHERE name = ?',(name,)).fetchone()
        return self.rowToJson(row) if row is not None else row
    
    def delete(self, ids) -> bool:
        try:
            self.conn.execute("DELETE FROM rules WHERE id IN (%s)" %
                           ','.join('?'*len(ids)),ids)
            self.conn.commit()
            for root, dirs, files in os.walk(RULE_DIRECTORY):
                for id in ids:
                    if str(id) in files:
                        os.remove(os.path.join(root, str(id)))
                        print(f"File {id} found and removed at {root}")
        except OSError:
            print("File not found")
            pass
        return True
    
    def getFullPath(self,id:str) -> str:
        return os.path.join(f"{RULE_DIRECTORY}/{id}")
    
    def update(self, id:str,payload) -> bool:
        if (payload['name'] is not None):
            self.conn.execute('UPDATE rules SET name = ?, description = ?, updated = ? WHERE id = ?',(payload['name'],"hi world",datetime.datetime.now(),str(id)))
        else:
            self.conn.execute('UPDATE rules SET description = ?, updated = ? WHERE id = ?',("hi world",datetime.datetime.now(),str(id)))
        self.conn.commit()
        file = open(self.getFullPath(id),"w")
        lines = payload['content'].readlines()
        for line in lines:
            file.write(line)
        return True
