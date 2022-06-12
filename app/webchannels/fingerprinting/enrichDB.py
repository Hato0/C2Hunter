from pysondb import db
from jarm.scanner.scanner import Scanner
import requests, logging, json, asyncio
import pandas as csvSort

logging.basicConfig(filename='app.log', filemode='w',format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO)

#DBTemplate : {"Malware":"","JARM Signature":[],"JA3 Signature":[],"JA3S Signature":[]}
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
            logging.info("  [*] Step 1 : Success")
    dataDownload = requests.get("https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv")
    if dataDownload.status_code != 200:
        logging.error(" [-] Failed step2")
    else:
        with open("feeds/abusechJA3Data.txt", "w") as dataFile:
            for line in dataDownload.iter_lines():
                if b'#' not in line and len(line) != 0:
                        toIngest = line.decode('utf-8').split(',')
                        dataFile.write(f'{toIngest[0]},{toIngest[3]}\n')
            logging.info("  [*] Step 2 : Success")
    for tool in tools:
        logging.info(f"[+] Downloading additional IOC for {tool} ...")
        payload = json.loads('{"query": "malwareinfo", "malware": ""}')
        payload["malware"] = tool
        data = requests.post("https://threatfox-api.abuse.ch/api/v1/", json=payload).json()
        if data['query_status'] != "ok":
            logging.error(" [-] Failed step3")
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
                        elem['ioc'] = elem['ioc'].split('/')[0]
                        dataFile.write(f""""{elem['ioc']}",{port},"{elem['malware_printable']}"\n""")
    logging.info("  [*] Step 3 : Success")

def sortByMalware(file, mode):
    if mode==1:
        csvData = csvSort.read_csv(file)
    elif mode ==2:
        csvData = csvSort.read_csv(file, names=['JA3','malware'])
    csvData.sort_values(['malware'], axis=0, inplace=True)
    return csvData
    
def getC2Signatures(url, port):
    jarmSign = []
    logging.getLogger('asyncio').setLevel(logging.CRITICAL)
    for i in range (0,3):
        if port == None:
            try:
                jarm = asyncio.get_event_loop().run_until_complete(Scanner.scan_async(url, 80, timeout=5, suppress=True))
                jarmSign.append(jarm[0])
            except Exception:
                logging.error(f"  [-] {url} couldn't be scan (timeout) ")
                break
        else:
            try:
                jarm = asyncio.get_event_loop().run_until_complete(Scanner.scan_async(url, port, timeout=5, suppress=True))
                jarmSign.append(jarm[0])
            except Exception:
                logging.error(f"  [-] {url} couldn't be scan (timeout) ")
                break

    if len(set(jarmSign)) == 1:
        return jarmSign[0]
    else:
        logging.warning(f"  [-] {url} is performing jarm escaping ")
            
def updateJARM(csvData):
    signDatas = []
    cnt = 0
    for index,row in csvData.iterrows():
        if cnt == 0:
            malware = row['malware']
            logging.info(f"  [-] Gathering signatures database for {malware}...")
        cnt +=1
        if malware != row['malware']:
            updateDatabase(signDatas, malware, "jarm")
            signDatas = []
            cnt = 0
        jarmSign = getC2Signatures(row['dst_ip'], row['dst_port'])
        if jarmSign not in signDatas and jarmSign != "00000000000000000000000000000000000000000000000000000000000000" and jarmSign is not None:
            signDatas.append(jarmSign)
    updateDatabase(signDatas, malware, "jarm")

def updateJA3(csvData):
    signDatas = []
    cnt = 0
    for index,row in csvData.iterrows():
        if cnt == 0:
            malware = row['malware']
            logging.info(f"  [-] Gathering signatures database for {malware}...")
        cnt +=1
        if malware != row['malware']:
            updateDatabase(signDatas, malware, "ja3")
            signDatas = []
            cnt = 0
        ja3Sign = row['JA3']
        if ja3Sign not in signDatas and ja3Sign is not None:
            signDatas.append(ja3Sign)
    updateDatabase(signDatas, malware, "ja3")


def updateDatabase(signDatas, malware, type):
    logging.info(f"  [-] Updating signatures database for {malware}...")
    signatureDB=db.getDb("./signatureDatabase.json")
    existingData = signatureDB.getByQuery({"Malware": malware})
    if type == "jarm":
        if len(existingData) == 0:
            newItem = {"Malware": malware ,"JARM Signature": signDatas,"JA3 Signature":[],"JA3S Signature":[]}
            itemId = signatureDB.add(newItem)
        else:
            for signature in signDatas:
                if signature not in existingData[0]['JARM Signature']:
                    existingData[0]['JARM Signature'].append(signature)
            itemId = signatureDB.updateByQuery(db_dataset={"Malware": malware}, new_dataset=existingData[0])
    elif type == "ja3":
        if len(existingData) == 0:
            newItem = {"Malware": malware ,"JARM Signature": [],"JA3 Signature":signDatas,"JA3S Signature":[]}
            itemId = signatureDB.add(newItem)
        else:
            for signature in signDatas:
                if signature not in existingData[0]['JA3 Signature']:
                    existingData[0]['JA3 Signature'].append(signature)
            itemId = signatureDB.updateByQuery(db_dataset={"Malware": malware}, new_dataset=existingData[0])

if __name__ == "__main__":
    logging.info("[+] Starting database enrichment ...")
    logging.info("[+] Downloading newest data ...")
    downloadMaterials()
    logging.info("[+] Updating JA3 database ...")
    csvData = sortByMalware("feeds/abusechJA3Data.txt", 2)
    updateJA3(csvData)
    logging.info("[+] Gathering JARM signatures ...")
    csvData = sortByMalware("feeds/abusechData.txt", 1)
    updateJARM(csvData)
    logging.info("[+] Database update done")