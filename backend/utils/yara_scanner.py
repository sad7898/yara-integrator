import json
import os
from typing import IO
import yara
import uuid
from utils import dex2jar

RULE_DIRECTORY = "rules"
def getRules():
    ruleFiles = os.listdir(os.path.join(f"{RULE_DIRECTORY}"))
    return {filename.split(".")[0]:os.path.join(f"{RULE_DIRECTORY}/{filename}") for filename in ruleFiles}


def scan(filename:str,stream:IO):
    dirPath,decompiledApkPath = dex2jar.decompileApk(filename,stream)
    ruleMap = getRules()
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
    # check if file name already exists!
    fullPath = os.path.join("rules",name)
    file = open(fullPath,"wb")
    lines = stream.readlines()
    for line in lines:
        file.write(line)
    return True
        
    


    
    
    