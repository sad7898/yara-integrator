from io import TextIOWrapper
import os
import sqlite3
from typing import IO
import datetime
from app import get_db
RULE_DIRECTORY = "rules"
class Repository:
    def __init__(self):
        self.conn = get_db()

    def insert(self,name:str,stream: IO):
        fullPath = os.path.join("rules",name)
        file = open(fullPath,"wb")
        lines = stream.readlines()
        for line in lines:
            file.write(line)
        return True

    def list(self):
        ruleFiles = os.listdir(os.path.join(RULE_DIRECTORY))
        return {filename.split(".")[0]:os.path.join(f"{RULE_DIRECTORY}/{filename}") for filename in ruleFiles}
    
    def searchByName(self,name="") -> IO | None:
        for _, _, files in os.walk(RULE_DIRECTORY):
            for file in files:
                if file.split(".")[0] == name:
                    return open(os.path.join(f"{RULE_DIRECTORY}/{file}"),"r")
        return None
    
    def delete(self, name:str) -> bool:
        for root, dirs, files in os.walk(RULE_DIRECTORY):
            if name in files:
                os.remove(os.path.join(root, name))
                print(f"File {name} found and removed at {root}")
                return True
        return False

    def update(self, name:str,stream: IO) -> bool:
        file = open(os.path.join(f"{RULE_DIRECTORY}/{name}"),"wb")
        lines = stream.readlines()
        for line in lines:
            file.write(line)
        return True
