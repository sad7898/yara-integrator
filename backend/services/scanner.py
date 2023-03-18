import json
import os
from typing import IO
import yara
import uuid
from utils import dex2jar
from repository import rule
ruleRepository = rule.Repository()



def scan(filename:str,stream:IO):
    dirPath,decompiledApkPath = dex2jar.decompileApk(filename,stream)
    ruleMap = ruleRepository.list()
    rules = yara.compile(filepaths=ruleMap)
    if decompiledApkPath is None or dirPath is None:
        matches = rules.match(data=stream.read())
    else:
        matches = rules.match(filepath=decompiledApkPath)
    result = {}
    print(matches)
    for match in matches:   
        if match.namespace in result:
            result[match.namespace].append(match.rule)
        else:
            result[match.namespace] = [match.rule]
    if (dirPath is not None):
        dex2jar.cleanTempDir(dirPath)
    return result

def addRule(name: str,stream: IO) -> bool:
    try:
        yara.compile(source=stream.read())
    except yara.SyntaxError:
        return False
    return ruleRepository.insert(name,stream)

def getRules():
   ruleMap = ruleRepository.list()
   return [{"name": rule,"path":ruleMap[rule]} for rule in ruleMap]
def searchRuleByFilename(name: str):
    file = ruleRepository.searchByName(name)
    if (file is not None):
        return {
            "name": name,
            "content": file.read()
        }
    return None

        
    


    
    
    