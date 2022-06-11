from pysondb import db
from jarm.scanner.scanner import Scanner
import requests, logging, glob, json

signatureDB=db.getDb("./signatureDatabase.json")
logging.basicConfig(filename='app.log', filemode='w',format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO)

#DBTemplate : {"Tool name":"","JARM Signature":[],"JA3 Signature":[],"JA3S Signature":[]}
def downloadMaterials():
    logging.info("[+] Downloading abuse.ch C2 DB ...")
    tools = ["get2","Cobalt Strike","PoshC2","qbot","Emotet"]
    dataDownload = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")  
    if dataDownload.status_code != 200:
        logging.error(" [-] Failed step1")
    else:
        with open("feeds/abusechData.txt", "w") as dataFile:
            for line in dataDownload.iter_lines():
                if b'#' not in line and len(line) != 0:
                    if b"online" in line:
                        toIngest = line.decode('utf-8').split(',')
                        dataFile.write(f'{toIngest[1]},{toIngest[2]},{toIngest[5]}\n')
            logging.info("  [*] Success")
    for tool in tools:
        payload = json.loads('{"query": "malwareinfo", "malware": ""}')
        payload["malware"] = tool
        data = requests.post("https://threatfox-api.abuse.ch/api/v1/", json=payload).json()
        if data['query_status'] != "ok":
            logging.error(" [-] Failed step2")
        else:
            for elem in data["data"]:
                with open("feeds/abusechData.txt", "a") as dataFile:
                    port = None
                    if "C&C" in elem["threat_type_desc"]:
                        if 'https' in elem['ioc']:
                            port = 443
                            elem['ioc'] = elem['ioc'].replace('https://','')
                        elif 'http' in elem['ioc']:
                            port = 80
                            elem['ioc'] = elem['ioc'].replace('http://','')
                        if ':' in elem['ioc']:
                            port = elem['ioc'].split(':')[1].split('/')[0]
                            elem['ioc'] = elem['ioc'].replace(f':{port}','')
                        dataFile.write(f""""{elem['ioc']}",{port},"{elem['malware_printable']}"\n""")

    logging.info("  [*] Success")

def sortByMalware():
    pass

def getC2Adresses():
    pass

def getC2Signatures():
    pass

def updateDatabase():
    pass




