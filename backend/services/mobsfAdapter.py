
import json
from typing import IO
from io import BytesIO, StringIO
import requests
import os
from flask import abort

class MobSFAdapter:
    def __init__(self):
        self.apiKey = os.environ['MOBSF_API_KEY']
        self.mobsfClient = os.environ['MOBSF_API_URL']
    def upload(self,filename:str,file:IO):
        file.seek(0)
        files=[
        ('file',(filename,file,'application/octet-stream'))
        ]
        headers = {'Authorization': self.apiKey}
        response = requests.post(f'{self.mobsfClient}/api/v1/upload', files=files,headers=headers)
            
        if response.status_code == 200:
            print(response.json())
            return response.json()
        else:
            print(response.json())
            abort(500,description=f'Error sending file to MobSF: {response.status_code} {response.reason}')

    def scan(self,hash,scanType,filename):
        headers = {'Authorization': self.apiKey}
        data = {
            "hash":hash,
            "scan_type":scanType,
            "file_name":filename
        }
        response = requests.post(f'{self.mobsfClient}/api/v1/scan',data=data,headers=headers)
        
        if response.status_code == 200:
            return response.content
        else:
            print(response.json())
            abort(500,description=f'Error scanning file with MobSF: {response.status_code} {response.reason}')
    
    def getPDFReport(self,hash):
        headers = {'Authorization': self.apiKey}
        response = requests.post(f'{self.mobsfClient}/api/v1/download_pdf',data={
            "hash":hash,
        },headers=headers)
        if response.status_code == 200:
            return BytesIO(response.content)
        else:
            print(response.json())
            abort(500,description=f'Error getting report from MobSF: {response.status_code} {response.reason}')
