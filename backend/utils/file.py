import os
import shutil
from typing import IO
import uuid

TEMP_APK_PATH = "tempApk"
ALLOWED_EXTENSIONS = {'apk','txt','pdf'}
def is_file_allowed(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def get_file_extension(filename):
    return  filename.rsplit('.', 1)[1].lower()



def saveApkToTemp(filename:str,stream:IO):
    id = uuid.uuid4().hex
    dirPath = os.path.join(TEMP_APK_PATH,id)
    os.makedirs(dirPath)
    path = os.path.join(dirPath,filename)
    tempApk = open(path,"wb")
    lines = stream.readlines()
    for line in lines:
        tempApk.write(line)
    return id,filename

def cleanTempDir(dirId: str):
    shutil.rmtree(os.path.join(TEMP_APK_PATH,dirId))
