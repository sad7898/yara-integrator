import os
import sys
import io
import subprocess
from typing import IO
import uuid
import shutil
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

def decompileApk(filename:str,apk: IO) -> IO:
    if (get_file_extension(filename) != "apk"):
        return None,None
    output = io.BytesIO()
    with tempfile.TemporaryDirectory() as tmpdirname:
        apkPath = saveApkToTemp(os.path.join(tmpdirname,filename),apk)
        resultFilePath = os.path.join(tmpdirname,f"{filename}-decompiled")
        cmd = getCmdStr()
        try:
            process = subprocess.run(args=[cmd,"-f",apkPath,"-o",resultFilePath],capture_output=True)
            decompiledFile = open(resultFilePath,"rb")
            lines = decompiledFile.readlines()
            for line in lines:
                output.write(line)
            decompiledFile.close()
            output.seek(0)
            return output
        except Exception as e:
            print(e)
            return None
  

