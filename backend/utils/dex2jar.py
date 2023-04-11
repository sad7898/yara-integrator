import os
import sys
import io
import subprocess
from typing import IO
import uuid
import shutil
import zipfile
import tempfile

from .file import get_file_extension

TEMP_APK_PATH = "tempApk"

def getCmdStr() -> str:
    if sys.platform == 'win32':
        return "d2j-dex2jar.bat"
    return "d2j-dex2jar.sh"


def saveApkToTemp(path:str,stream:IO):
    tempApk = open(path,"wb")
    lines = stream.readlines()
    for line in lines:
        tempApk.write(line)
    tempApk.close()
    return path

def decompileApk(path: str) -> IO:
    dirname = os.path.dirname(path)
    filename = os.path.basename(path)
    if (get_file_extension(filename) != "apk"):
        return None
    resultFilePath = os.path.join(dirname,f"{filename}-decompiled")
    cmd = getCmdStr()
    try:
        process = subprocess.run(args=[cmd,"-f",path,"-o",resultFilePath],capture_output=True)
        return resultFilePath
    except Exception as e:
        return None

    
    
  

