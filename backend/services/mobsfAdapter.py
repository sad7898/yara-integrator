
import json
from typing import IO
from io import BytesIO, StringIO
import requests
import os
from flask import abort

class MobSFAdapter:
    def safeRequest(func):
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
            except Exception as e:
                abort(400,description=f"Cannot connect to MobSF api with {os.environ['MOBSF_API_URL']}")
            return result
        return wrapper
    @safeRequest
    def upload(self,filename:str,file:IO):
        file.seek(0)
        files=[
        ('file',(filename,file,'application/octet-stream'))
        ]
        headers = {'Authorization': os.environ['MOBSF_API_KEY']}
        url = os.environ['MOBSF_API_URL']
        response = requests.post(f'{url}/api/v1/upload', files=files,headers=headers)
            
        if response.status_code == 200:
            print(response.json())
            return response.json()
        else:
            print(response.json())
            abort(500,description=f'Error sending file to MobSF: {response.status_code} {response.reason}')
    @safeRequest
    def scan(self,hash,scanType,filename):
        headers = {'Authorization': os.environ['MOBSF_API_KEY']}
        url = os.environ['MOBSF_API_URL']
        data = {
            "hash":hash,
            "scan_type":scanType,
            "file_name":filename
        }
        response = requests.post(f'{url}/api/v1/scan',data=data,headers=headers)
        
        if response.status_code == 200:
            return response.content
        else:
            print(response.json())
            abort(500,description=f'Error scanning file with MobSF: {response.status_code} {response.reason}')
    @safeRequest
    def getPDFReport(self,hash):
        url = os.environ['MOBSF_API_URL']
        headers = {'Authorization': os.environ['MOBSF_API_KEY']}
        response = requests.post(f'{url}/api/v1/download_pdf',data={
            "hash":hash,
        },headers=headers)
        if response.status_code == 200:
            return BytesIO(response.content)
        else:
            print(response.json())
            abort(500,description=f'Error getting report from MobSF: {response.status_code} {response.reason}')
