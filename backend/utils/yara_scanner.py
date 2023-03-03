import json
import os
from typing import IO
import yara

RULE_DIRECTORY = "rules"
def get_rules():
    ruleFiles = os.listdir(os.path.join("backend/{RULE_DIRECTORY}"))
    return {filename.split(".")[0]:os.path.join("{RULE_DIRECTORY}/{filename}") for filename in ruleFiles}

def scan(stream:IO):
    ruleMap = get_rules()
    rules = yara.compile(filepaths=ruleMap)
    matches = rules.match(data=stream.read())
    result = {}
    for match in matches:   
        if match.namespace in result:
            result[match.namespace].append(match.rule)
        else:
            result[match.namespace] = [match.rule]
    return result

def add_rule(name: str,stream: IO):
    fullPath = os.path.join("rules",name)
    file = open(fullPath,"w")
    lines = stream.readlines()
    for line in lines:
        file.write(line)
    return
        
    
    
    
    
    