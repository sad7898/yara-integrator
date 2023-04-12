import io
import os

from typing import IO
import zipfile
import yara
import tempfile
from .reporter import Reporter
from ..utils import dex2jar,file as fileUtils
from ..repository import rule

from flask import abort
class Match():
    def __init__(self,namespace: str,rule: str,description: str,location: str):
        self.namespace = namespace
        self.description = description
        self.rule = rule
        self.location = location
class ScanResult():
    def __init__(self):
        self.dict = {}
    def addMatches(self,matches: "list[Match]"):
        for match in matches:
            if match.namespace in self.dict:
                self.dict[match.namespace]['rules'].append(match.rule)
                self.dict[match.namespace]['locations'].append(match.location)
            else:
                self.dict[match.namespace] = {
                        "rules": [match.rule],
                        "description": match.description,
                        "locations": [match.location]
            }
    def get(self):
        return self.dict
        

class Scanner:
    def __init__(self,ruleRepository: rule.Repository):
        self.ruleRepository = ruleRepository
    def _matchYaraRules(self,file: IO,compiledRules):
        matches = compiledRules.match(data=file.read())
        return matches
   
    def _extractApk(self,apkPath:str,ignoreDex=False):
        print(f"Extracting APK from {apkPath}")
        dataPath = os.path.join(os.path.dirname(apkPath),'apk-data')
        with zipfile.ZipFile(apkPath) as apk:
            for member in apk.infolist():
                if ignoreDex and member.filename.endswith('dex'):
                    continue 
                apk.extract(member, dataPath)

            for root, dirs, files in os.walk(dataPath):
                for filename in files:
                    filePath = os.path.join(root, filename)
                    with open(filePath, 'r',encoding='iso-8859-1') as file:
                        yield file,filename
  
    def _extractJar(self,jarPath):
        print(f"Extracting JAR from {jarPath}")
        with zipfile.ZipFile(jarPath) as jar:
            jarDataPath = os.path.join(os.path.dirname(jarPath),'jar-data')
            jar.extractall(jarDataPath)
            for root, dirs, files in os.walk(jarDataPath):
                for filename in files:
                    filePath = os.path.join(root, filename)
                    with open(filePath, 'r',encoding='iso-8859-1') as file:
                        yield file,filename
        
    def scan(self,filename:str,stream:IO,shouldDecompile: bool):
        stream.seek(0)
        rules = self.ruleRepository.list()
        compiledRules = yara.compile(filepaths={rule['name']:self.ruleRepository.getFullPath(rule['id']) for rule in rules})
        with tempfile.TemporaryDirectory() as tempdir:
            result = ScanResult()
            apkPath = dex2jar.saveApkToTemp(os.path.join(tempdir,filename),stream)
            for file,name in self._extractApk(apkPath,shouldDecompile):
                rawMatches = self._matchYaraRules(file,compiledRules)
                matches = [Match(match.namespace,match.rule,[rule for rule in rules if rule['name']==match.namespace][0]['description'],name) for match in rawMatches]
                result.addMatches(matches)
            if shouldDecompile:
                jarPath = dex2jar.decompileApk(apkPath)
                if (jarPath is not None):
                    for file,name in self._extractJar(jarPath):
                        rawMatches = self._matchYaraRules(file,compiledRules)
                        matches = [Match(match.namespace,match.rule,[rule for rule in rules if rule['name']==match.namespace][0]['description'],name) for match in rawMatches]
                        result.addMatches(matches)
            scans = result.get()
            for namespace in scans:
                scans[namespace]['rules'] = list(set(scans[namespace]['rules']))
                scans[namespace]['locations'] = list(set(scans[namespace]['locations']))
            return scans

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
    




        
    


    
    
    