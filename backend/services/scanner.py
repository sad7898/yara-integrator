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
    rules = ruleRepository.list()
    rules = yara.compile(filepaths={rule['name']:ruleRepository.getFullPath(rule['id']) for rule in rules})
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

def addRule(name: str,stream: IO,description: str) -> bool:
    if (ruleRepository.searchByName(name) is not None):
        abort(400,description="File with this name already exists.")
    try:
        yara.compile(file=stream)
    except yara.SyntaxError:
        abort(400,description="Invalid Syntax")
    stream.seek(0)
    return ruleRepository.insert(name,description,stream)

def getRules():
   ruleMap = ruleRepository.list()
   return ruleMap

def updateRule(id:str,payload: dict) -> bool:
    stream = io.StringIO(payload['content'])
    rule = ruleRepository.searchById(id)
    if (rule == None):
        abort(400,description=f"Cannot find rule with id {id}")
    if (payload['name'] != rule['name'] and ruleRepository.searchByName(payload['name']) is not None):
        abort(400,description=f"File with name {payload['name']} already exist")
    try:
        yara.compile(source=payload['content'])
    except yara.SyntaxError:
       abort(400,description="Invalid Syntax")
    stream.seek(0)
    return ruleRepository.update(id,{"name":payload['name'] if payload['name'] != rule['name'] else None,"content":stream,"description":payload['description']})

def deleteRules(ids: list[str]):
    return ruleRepository.delete(ids)

def searchRuleById(id:str):
    rule = ruleRepository.searchById(id)
    if (rule is not None):
        print(rule)
        rule['content'] = open(ruleRepository.getFullPath(rule['id']),'r').read()
        return rule


        
    


    
    
    