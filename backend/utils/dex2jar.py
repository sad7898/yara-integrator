import os
import sys
import io
import subprocess
from typing import IO
import uuid
import shutil

from backend.utils.file import get_file_extension

TEMP_APK_PATH = "tempApk"

def getCmdStr() -> str:
    if sys.platform == 'win32':
        return "d2j-dex2jar.bat"
    return "sh d2j-dex2jar"


def saveApkToTemp(filename:str,stream:IO):
    id = uuid.uuid4().hex
    dirPath = os.path.join(TEMP_APK_PATH,id)
    os.mkdir(dirPath)
    path = os.path.join(dirPath,filename)
    tempApk = open(path,"wb")
    lines = stream.readlines()
    for line in lines:
        tempApk.write(line)
    return id,filename

def decompileApk(filename:str,apk: IO) -> str:
    if (get_file_extension(filename) != "apk"):
        return None,None
    dirId,filename = saveApkToTemp(filename,apk)
    resultFilePath = os.path.join(TEMP_APK_PATH,dirId,f"{filename}-decompiled")
    cmd = getCmdStr()
    process = subprocess.run(args=[cmd,"-f",os.path.join(TEMP_APK_PATH,dirId,filename),"-o",resultFilePath],capture_output=True)
    if process.stderr is not None:
        return dirId,None
    else:
        return dirId,resultFilePath
    


def cleanTempDir(dirId: str):
    shutil.rmtree(os.path.join(TEMP_APK_PATH,dirId))
