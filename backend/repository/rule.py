from io import TextIOWrapper
import os
import sqlite3
from typing import IO
import datetime
RULE_DIRECTORY = "rules"
class Repository:

    def insert(self,name:str,stream: IO):
        fullPath = os.path.join("rules",name)
        file = open(fullPath,"wb")
        lines = stream.readlines()
        for line in lines:
            file.write(line)
        return True

    def list(self):
        ruleFiles = os.listdir(os.path.join(RULE_DIRECTORY))
        return {filename:self.getFullPath(filename) for filename in ruleFiles}
    
    def searchByName(self,name="") -> IO | None:
        for _, _, files in os.walk(RULE_DIRECTORY):
            for file in files:
                if file == name:
                    return open(os.path.join(f"{RULE_DIRECTORY}/{file}"),"r")
        return None
    
    def delete(self, names) -> bool:
        for root, dirs, files in os.walk(RULE_DIRECTORY):
            for name in names:
                if name in files:
                    os.remove(os.path.join(root, name))
                    print(f"File {name} found and removed at {root}")
        return True
    
    def getFullPath(self,filename:str) -> str:
        return os.path.join(f"{RULE_DIRECTORY}/{filename}")
    
    def update(self, currentName:str,payload) -> bool:
        latestName = currentName
        if (currentName != payload['name']):
            try:
                os.rename(self.getFullPath(currentName), self.getFullPath(payload['name']))
                latestName = payload['name']
            except FileExistsError:
                return False
        file = open(self.getFullPath(latestName),"w")
        lines = payload['content'].readlines()
        for line in lines:
            file.write(line)
        return True
