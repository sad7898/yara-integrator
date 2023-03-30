from io import StringIO

from flask import Flask, abort, jsonify, request,g
from werkzeug.datastructures import FileStorage
from flask_cors import CORS
from .utils import file as fileUtils
from .db import init_db,db
from .services import scanner as scannerService
from .repository import rule
def create_app(test_config=None):
    init_db.init_db()
    connection = db.get_db()
    ruleRepository = rule.Repository(connection)
    scanner = scannerService.Scanner(ruleRepository)
    app = Flask(__name__)
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
            description = request.form['description']
            file = request.files['file']
            if file.filename == "":
                abort(400,description="invalid file format")         
            return {"success": scanner.addRule(file.filename if name is None else name,file.stream,description)}

    @app.route("/yara",methods=['GET'])
    def getRules():
        if request.method == 'GET':
            return {"data":scanner.getRules()}

    @app.route("/yara/<id>",methods=['GET'])
    def searchRule(id:str):
        if request.method == 'GET':
            return {"data":scanner.searchRuleById(id)}

    @app.route("/yara/<id>",methods=['PUT'])
    def updateRule(id:str):
        if (request.method == 'PUT'):
            description = request.form['description']
            newFilename = request.form['name']
            content = request.form['content']
            result = scanner.updateRule(id,{"name":newFilename,"content":content,"description":description})
            return {"success":result}

    @app.route("/yara/remove",methods=['POST'])
    def deleteRule():
        if (request.method=='POST'):
            fileIds = request.json['data']
            return {"success":scanner.deleteRules(fileIds)}
     
    return app
