import os
import time
from typing import IO

from celery import Task

from ..utils.file import TEMP_APK_PATH,cleanTempDir

from ..services.mobsfAdapter import MobSFAdapter

from ..services.scanner import Scanner

class ScanTask(Task):
    def __init__(self,scanner: Scanner,mobsf: MobSFAdapter):
        self.scanner = scanner
        self.mobsf = mobsf
    def run(self,dirId:str,filename:str):
        self.update_state(state='PROGRESS',
                    meta={'current': 0, 'total': 2})
        file = open(os.path.join(TEMP_APK_PATH,dirId,filename))
        yaraResult = self.scanner.scan(filename,file,True)
        self.update_state(state='PROGRESS',
                    meta={'current': 1, 'total': 2})
        # # res = mobsf.upload(filename,stream)
        time.sleep(10000)
        # # mobsf.scan(res['hash'],res['scan_type'],res['file_name'])
        self.update_state(state='PROGRESS',
                    meta={'current': 2, 'total': 2})
        file.close()
        cleanTempDir(dirId)
        return {"mobsfHash":"hello","yara":yaraResult}








    