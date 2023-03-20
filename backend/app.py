from io import StringIO
import json
import sqlite3
from flask import Flask, abort, jsonify, request,g
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from flask_cors import CORS
import os
from utils import file as fileUtils
from services import scanner
     
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = '/app/apk'
CORS(app)



@app.errorhandler(400)
def bad_request(e):
    return jsonify(error=str(e)), 400
@app.route('/')
def hello():
	return "Hello World!"

@app.route('/scan',methods=['POST'])
def scan_apk():
    if request.method == 'POST':
        if 'file' not in request.files:
            abort(400,description="File not found")
        file = request.files['file']
        if file.filename == "" or not fileUtils.is_file_allowed(file.filename):
            abort(400,description="invalid file format")            
        return scanner.scan(file.filename,file.stream)
        
@app.route('/yara',methods=["POST"])
def addRule():
    if request.method == 'POST':
        if 'file' not in request.files:
            abort(400,description="File not found")
        name = request.form['name']
        file = request.files['file']
        if file.filename == "":
            abort(400,description="invalid file format")         
        return {"success": scanner.addRule(file.filename if name is None else name,file.stream)}

@app.route("/yara",methods=['GET'])
def getRules():
     if request.method == 'GET':
          return {"data":scanner.getRules()}

@app.route("/yara/<filename>",methods=['GET'])
def searchRule(filename:str):
     if request.method == 'GET':
          return {"data":scanner.searchRuleByFilename(filename)}

@app.route("/yara/<currentFilename>",methods=['PUT'])
def updateRule(currentFilename:str):
     if (request.method == 'PUT'):
        newFilename = request.form['name']
        content = request.form['content']
        result = scanner.updateRule(currentFilename,{"name":newFilename,"content":content})
        return {"success":result}
          



if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8000)