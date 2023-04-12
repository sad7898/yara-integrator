import os
import subprocess
import sys
from typing import IO

from ..utils.file import get_file_extension


def getCmdStr() -> str:
    if sys.platform == 'win32':
        return "apktool.bat"
    return "apktool"



def extractApk(path: str) -> str:
    dirname = os.path.dirname(path)
    filename = os.path.basename(path)
    if (get_file_extension(filename) not in ["apk","jar"]):
        return None
    resultDir = os.path.join(dirname,"extracted-apk")
    cmd = getCmdStr()
    try:
        popen = subprocess.Popen([cmd,"d",path,"-o",resultDir],shell=True,stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        while popen.poll() is None:
            line = popen.stdout.readline().decode()
            if line.startswith('I: Copying original files'):
                popen.communicate(b'\r\n')
        return resultDir
    except Exception as e:
        print(e)
        return None
