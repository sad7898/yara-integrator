import io
import json
import os
from typing import IO
import yara
import uuid
from utils import dex2jar
from repository import rule
from flask import abort

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
        yara.compile(file=stream)
    except yara.SyntaxError:
        abort(400,description="Invalid Syntax")
    stream.seek(0)
    return ruleRepository.insert(name,stream)

def getRules():
   ruleMap = ruleRepository.list()
   return [{"name": rule,"path":ruleMap[rule]} for rule in ruleMap]

def updateRule(currentFilename:str,payload: dict) -> bool:
    stream = io.StringIO(payload['content'])
    if (searchRuleByFilename(currentFilename) == None):
        abort(400,description=f"Cannot find rule with name {currentFilename}")
    try:
        yara.compile(source=payload['content'])
    except yara.SyntaxError:
       abort(400,description="Invalid Syntax")
    stream.seek(0)
    return ruleRepository.update(currentFilename,{"name":payload['name'],"content":stream})

def searchRuleByFilename(name: str):
    file = ruleRepository.searchByName(name)
    if (file is not None):
        return {
            "name": os.path.basename(file.name),
            "content": file.read()
        }
    return None

        
    


    
    
    