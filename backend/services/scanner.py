import io

from typing import IO
import yara
from ..utils import dex2jar
from ..repository import rule
from flask import abort


class Scanner:
    def __init__(self,ruleRepository: rule.Repository):
        self.ruleRepository = ruleRepository

    def scan(self,filename:str,stream:IO):
        dirPath,decompiledApkPath = dex2jar.decompileApk(filename,stream)
        rules = self.ruleRepository.list()
        rules = yara.compile(filepaths={rule['name']:self.ruleRepository.getFullPath(rule['id']) for rule in rules})
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

    def addRule(self,name: str,stream: IO,description: str) -> bool:
        if (self.ruleRepository.searchByName(name) is not None):
            abort(400,description="File with this name already exists.")
        try:
            yara.compile(file=stream)
        except yara.SyntaxError:
            abort(400,description="Invalid Syntax")
        stream.seek(0)
        return self.ruleRepository.insert(name,description,stream)

    def getRules(self):
        ruleMap = self.ruleRepository.list()
        return ruleMap

    def updateRule(self,id:str,payload: dict) -> bool:
        stream = io.StringIO(payload['content'])
        rule = self.ruleRepository.searchById(id)
        if (rule == None):
            abort(400,description=f"Cannot find rule with id {id}")
        if (payload['name'] != rule['name'] and self.ruleRepository.searchByName(payload['name']) is not None):
            abort(400,description=f"File with name {payload['name']} already exist")
        try:
            yara.compile(source=payload['content'])
        except yara.SyntaxError:
            abort(400,description="Invalid Syntax")
        stream.seek(0)
        return self.ruleRepository.update(id,{"name":payload['name'] if payload['name'] != rule['name'] else None,"content":stream,"description":payload['description']})

    def deleteRules(self,ids: list):
        return self.ruleRepository.delete(ids)

    def searchRuleById(self,id:str):
        rule = self.ruleRepository.searchById(id)
        if (rule is not None):
            try:
                rule['content'] = open(self.ruleRepository.getFullPath(rule['id']),'r').read()
            except FileNotFoundError:
                self.ruleRepository.delete([id])
                abort(404,description="Cannot find the rule you are looking for, please refresh the page and try again.")
            return rule


        
    


    
    
    