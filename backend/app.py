from io import StringIO
import json
from flask import Flask, abort, jsonify, request
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from flask_cors import CORS
import os
from utils import file as fileUtils
from utils import yara_scanner

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
        return yara_scanner.scan(file.filename,file.stream)
        
@app.route('/yara',methods=["POST"])
def addRule():
    if request.method == 'POST':
        if 'file' not in request.files:
            abort(400,description="File not found")
        file = request.files['file']
        if file.filename == "":
            abort(400,description="invalid file format")            
        return str(yara_scanner.addRule(file.filename,file.stream))




if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8000)