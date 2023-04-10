import io
import os

from typing import IO
import zipfile
import yara
import tempfile
from .reporter import Reporter
from ..utils import dex2jar
from ..repository import rule
from flask import abort


class Scanner:
    def __init__(self,ruleRepository: rule.Repository):
        self.ruleRepository = ruleRepository
    def _matchYaraRules(self,file: IO,rules,compiledRules=None,result=None):
        if compiledRules is None:
            compiledRules = yara.compile(filepaths={rule['name']:self.ruleRepository.getFullPath(rule['id']) for rule in rules})
        matches = compiledRules.match(data=file.read())
        if result is None:
            result = {}
        for match in matches:   
            if match.namespace in result:
                result[match.namespace]['rules'].append(match.rule)
            else:
                result[match.namespace] = {
                    "rules": [match.rule],
                    "description": [rule for rule in rules if rule['name'] == match.namespace][0]['description']
                }
        for namespace in result:
            result[namespace]['rules'] = list(set(result[namespace]['rules']))
        return result
    def scanZip(self,zip: IO):
        with tempfile.TemporaryDirectory() as tempdir:
            jar = zipfile.ZipFile(zip)
            jar.extractall(tempdir)
            rules = self.ruleRepository.list()
            compiledRules = yara.compile(filepaths={rule['name']:self.ruleRepository.getFullPath(rule['id']) for rule in rules})
            result = {}
            for root, dirs, files in os.walk(tempdir):
                print(f"scanning files in dir {dirs}")
                # Loop through all files in the current directory
                for filename in files:
                    file_path = os.path.join(root, filename)
                    with open(file_path, 'r',encoding='iso-8859-1') as file:
                        self._matchYaraRules(file,rules,compiledRules,result)
            
            return result
                        
                    
    def scan(self,filename:str,stream:IO,shouldDecompile: bool):
        stream.seek(0)
        if shouldDecompile:
            zip = dex2jar.decompileApk(filename,stream)
            if zip is not None:
                return self.scanZip(zip)
        rules = self.ruleRepository.list()
        return self._matchYaraRules(stream,rules)

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
    




        
    


    
    
    