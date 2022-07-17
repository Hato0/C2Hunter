# -*- encoding: utf-8 -*-
from operator import contains
from WebInterface.home import blueprint
from flask import render_template, request
from flask_login import login_required
from jinja2 import TemplateNotFound
from WebInterface.home.models import Asset
import sqlite3
from sqlite3 import Error
import psutil
import subprocess
from threading import Thread

def createConnection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)
    return conn

def sortKey(elem):
    return elem[1]

def startProxy():
    subprocess.run(["node.exe", "app\webchannels\proxyAnalyzer\proxy.js"])

def createCron(script):
    subprocess.run(["crontab", "-l", ">", "mycron"])
    subprocess.run(["echo", f"0 1 * * * {script}", ">>", "mycron"])
    subprocess.run(["crontab", "mycron"])
    subprocess.run(["rm", "mycron"])
    



@blueprint.route('/index')
@blueprint.route('/index.html')
@login_required
def index():
    database = "app/webchannels/proxyAnalyzer/database.sqlite3"
    conn = createConnection(database)
    #checking proxy state
    isRunning = "node.exe" in (p.name() for p in psutil.process_iter())
    #Fetching malware datas
    malwareID = []
    malwareData = []
    maliciousURL = conn.execute(f'SELECT Id, lastSeen, sourceIP FROM proxyLogs WHERE isMalicious = 1').fetchall()
    allURL = conn.execute(f'SELECT Id, lastSeen, sourceIP, isMalicious FROM proxyLogs').fetchall()
    maliciousJA3 = conn.execute(f'SELECT DISTINCT ja3ID FROM malware_ja3').fetchall()
    maliciousJA3S = conn.execute(f'SELECT DISTINCT ja3sID FROM malware_ja3s').fetchall()
    maliciousJARM = conn.execute(f'SELECT DISTINCT jarmID FROM malware_jarm').fetchall()
    for URL in maliciousURL:
        signatureJARMID = conn.execute(f'SELECT jarmID from url_jarm where urlID = {URL[0]}').fetchall()
        signatureJA3ID = conn.execute(f'SELECT ja3ID from url_ja3 where urlID = {URL[0]}').fetchall()
        signatureJA3SID = conn.execute(f'SELECT ja3sID from url_ja3s where urlID = {URL[0]}').fetchall()
        if signatureJARMID:
            for signature in signatureJARMID:
                malwareID.append(conn.execute(f'SELECT malwareID from malware_jarm where jarmID = {signature[0]}').fetchall())   
        if signatureJA3ID:
            for signature in signatureJA3ID:
                malwareID.append(conn.execute(f'SELECT malwareID from malware_ja3 where ja3ID = {signature[0]}').fetchall())  
        if signatureJA3SID:
            for signature in signatureJA3SID:
                malwareID.append(conn.execute(f'SELECT malwareID from malware_ja3s where ja3sID = {signature[0]}').fetchall())  
        for elem in malwareID:
            for id in elem:
                name = conn.execute(f'SELECT name from malwareDB where Id = {id[0]}').fetchall()
                malwareData.append([name, URL[1], URL[2]])
    malwareData.sort(key=sortKey)
    alreadySeen = []
    finalMalwareData=[]
    for data in malwareData:
        for malwareName in data[0]:
            if malwareName[0] not in alreadySeen:
                alreadySeen.append(malwareName[0])
                finalMalwareData.append([malwareName[0],data[1],data[2]])
            else:
                index = [(i, malwareNameSearch.index(malwareName[0])) for i, malwareNameSearch in enumerate(finalMalwareData) if malwareName[0] in malwareNameSearch]
                finalMalwareData[index[0]][2].append(data[2])
    #checking if malicious URL have been log
    maliciousURLCount = len(maliciousURL)
    #checking number of malicious signature registered
    maliciousSignatureCount = len(maliciousJA3)
    maliciousSignatureCount += len(maliciousJA3S)
    maliciousSignatureCount += len(maliciousJARM)
    #Getting user data
    userData = []
    userAlreadySeen = []
    for elem in allURL:
        if elem[2] not in userAlreadySeen:
            userAlreadySeen.append(elem[2])
            if elem[3] != 1:
                userData.append([elem[2], "", 0 , 1])
            else:
                userData.append([elem[2], "", 1 , 1])
        else:
            index = [(i, clientSearch.index(elem[2])) for i, clientSearch in enumerate(userData) if elem[2] in clientSearch]
            if elem[3] != 1:
                userData[index[0][0]][3] += 1
            else:
                userData[index[0][0]][3] += 1
                userData[index[0][0]][2] += 1


    for elem in finalMalwareData:
        index = [(i, clientSearch.index(elem[2])) for i, clientSearch in enumerate(userData) if elem[2] in clientSearch]
        userData[index[0][0]][1] += elem[0]+" "

    return render_template('home/index.html', segment='index', proxyState=isRunning, maliciousURLCount=maliciousURLCount, maliciousSignatureCount=maliciousSignatureCount, malwareData=finalMalwareData, userData=userData)


@blueprint.route('/<template>', methods=['POST', 'GET'])
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'
        #Database setup
        database = "app/webchannels/proxyAnalyzer/database.sqlite3"
        conn = createConnection(database)
        # Detect the current page
        segment = get_segment(request)
        if 'proxy-management' in template:
            if request.method == "POST":
                option = request.form['icon-input']
                if option == "2":
                    for proc in psutil.process_iter():
                        if 'node.exe' in proc.name():
                            proc.kill()
                elif option == "1":
                    daemon = Thread(target=startProxy, daemon=True, name='proxy')
                    daemon.start()
            #Running check
            isRunning = "node.exe" in (p.name() for p in psutil.process_iter())
            #Signature registered
            maliciousJA3 = conn.execute(f'SELECT DISTINCT ja3ID FROM malware_ja3').fetchall()
            maliciousJA3S = conn.execute(f'SELECT DISTINCT ja3sID FROM malware_ja3s').fetchall()
            maliciousJARM = conn.execute(f'SELECT DISTINCT jarmID FROM malware_jarm').fetchall()
            maliciousSignatureCount = len(maliciousJA3)
            maliciousSignatureCount += len(maliciousJA3S)
            maliciousSignatureCount += len(maliciousJARM)
            #Malicious URL count
            maliciousURL = conn.execute(f'SELECT Id, lastSeen, sourceIP FROM proxyLogs WHERE isMalicious = 1').fetchall()
            maliciousURLCount = len(maliciousURL)
            return render_template("home/" + template, segment=segment, proxyState=isRunning, maliciousURLCount=maliciousURLCount, maliciousSignatureCount=maliciousSignatureCount)
        if 'proxy-logs' in template:
            data = conn.execute(f'SELECT * FROM proxyLogs').fetchall()
            return render_template("home/" + template, segment=segment, logs=data)
        if 'security-blacklist' in template:
            data = conn.execute(f'SELECT * FROM proxyLogs where isBlacklisted = 1').fetchall()
            return render_template("home/" + template, segment=segment, logs=data)
        if 'security-whitelist' in template:
            if request.method == 'POST':
                dict = request.form.to_dict()
                for item in dict.items():
                    if 'Blacklist' in item:
                        conn.execute(f"UPDATE proxyLogs SET isMalicious = 1, isBlacklisted = 1, isWhitelisted = 0 where URL = '{item[0]}';")
                    elif 'Remove' in item:
                        conn.execute(f"UPDATE proxyLogs SET isMalicious = 1, isBlacklisted = 0, isWhitelisted = 0 where URL = '{item[0]}';")
            conn.commit()
            data = conn.execute(f'SELECT * FROM proxyLogs where isWhitelisted = 1').fetchall()
            return render_template("home/" + template, segment=segment, logs=data)
        if 'security-blacklist' in template:
            if request.method == 'POST':
                dict = request.form.to_dict()
                for item in dict.items():
                    if 'Whitelist' in item:
                        conn.execute(f"UPDATE proxyLogs SET isMalicious = 1, isBlacklisted = 0, isWhitelisted = 1 where URL = '{item[0]}';")
                    elif 'Remove' in item:
                        conn.execute(f"UPDATE proxyLogs SET isMalicious = 1, isBlacklisted = 0, isWhitelisted = 0 where URL = '{item[0]}';")
            conn.commit()
            data = conn.execute(f'SELECT * FROM proxyLogs where isWhitelisted = 1').fetchall()
            return render_template("home/" + template, segment=segment, logs=data)
        if 'security-settings' in template:
            if request.method == 'POST':
                dict = request.form.to_dict()
                for item in dict.items():
                    if 'Dec' in item:
                        if 'Automatic' in item:
                            createCron("app/webchannels/brain.py -c 10 -m 0")
                        else:
                            pass
                    if 'Choi' in item:
                        if 'Automatic' in item:
                            createCron("app/webchannels/brain.py -c 10 -m 0")
                        else:
                            pass
                    if 'DB' in item:
                        if 'Automatic' in item:
                            createCron("app/webchannels/fingerprinting/databseBuild/enrichDB.py")
                        else:
                            pass
                    if 'Crit' in item:
                        pass
        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
