from glob import glob
import sqlite3
from sqlite3 import Error
import argparse
from threading import Thread

from numpy import sign
from fingerprinting.utils.jarmScan import JARMScan

parser = argparse.ArgumentParser(description="Brain of webchannels detection")
parser.add_argument('-c', '--criteria', help='Number of hours that an URL should be visited in the last 24h. Default = 10')
parser.add_argument('-m', '--mode', help='Auto or manual (0,1)')

args = parser.parse_args()

if args.criteria:
    criteria = args.criteria
else:
    criteria = 10
if args.mode:
    mode = args.mode
else:
    mode = 0

def createConnection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)
    return conn

def selectPotentialC2(conn):
    global criteria
    cur = conn.cursor()
    cur.execute(f"SELECT Id, URL FROM proxyLogs where foHoursSeen>={criteria};")
    rows = cur.fetchall()
    return rows

def getKnownSignature(conn, potentialC2):
    newPotentialC2 = []
    for IOC in potentialC2:
        if ':' not in IOC[1]:
            IOC = (IOC[0], IOC[1] + ':443')
        jarm = conn.execute('SELECT jarm.jarm \
                                    FROM jarmSignature jarm \
                                  INNER JOIN url_jarm url \
                                    ON jarm.Id = url.urlID \
                                  WHERE url.urlID = ?',
                                  (IOC[0],)).fetchall()
        ja3 = conn.execute('SELECT ja3.ja3 \
                                    FROM ja3Signature ja3 \
                                  INNER JOIN url_ja3 url \
                                    ON ja3.Id = url.urlID \
                                  WHERE url.urlID = ?',
                                  (IOC[0],)).fetchall()
        ja3s = conn.execute('SELECT ja3s.ja3s \
                                    FROM ja3sSignature ja3s \
                                  INNER JOIN url_ja3s url \
                                    ON ja3s.Id = url.urlID \
                                  WHERE url.urlID = ?',
                                  (IOC[0],)).fetchall()
        newPotentialC2.append(IOC + (jarm, ja3, ja3s))
    return newPotentialC2

def urlAnalyze(Id, URL, JARM, JA3, JA3S):
    print(f'    [-] Processing {URL}')
    global mode
    scanner = JARMScan(URL)
    if not JARM:
        JARM = scanner.generateJARM()
        if JARM:
            JARMResult = jarmAnalyze(JARM[0], Id)
    else:
        JARMResult = jarmAnalyze(JARM[0][0], Id)
    if JARMResult:
        database = "app/webchannels/proxyAnalyzer/database.sqlite3"
        conn = createConnection(database)
        cur = conn.cursor()
        if mode == 0:
            whitelistedTest = conn.execute(f"SELECT Id, URL FROM proxyLogs where URL = '{URL[0]}' and isWhitelisted = 1;").fetchall()
            if not whitelistedTest:
                cur.execute(f"UPDATE proxyLogs SET isMalicious = 1, isBlacklisted = 1 where URL = '{URL[0]}';")
            else:
                cur.execute(f"UPDATE proxyLogs SET isMalicious = 1 where URL = '{URL[0]}';")
        else:
            cur.execute(f"UPDATE proxyLogs SET isMalicious = 1 where URL = '{URL[0]}';")
        conn.commit()
        print(f"    [-] Malicious for JARM: {URL}")

def jarmAnalyze(signature, Id):
    database = "app/webchannels/proxyAnalyzer/database.sqlite3"
    conn = createConnection(database)
    cur = conn.cursor()
    isPresent = conn.execute(f'SELECT Id FROM jarmSignature WHERE jarm = "{signature}"').fetchall()
    if isPresent:
        isLinkToMalware = conn.execute(f'SELECT Id FROM malware_jarm WHERE jarmID = {isPresent[0][0]}').fetchall()
        if isLinkToMalware:
            return True
        else:
            return False
    else:
        cur.execute(f"INSERT INTO jarmSignature (jarm) VALUES ('{signature}')")
        rowIdSign = cur.lastrowid
        cur.execute(f"INSERT INTO url_jarm (jarmID, urlID) VALUES ({rowIdSign}, {Id})")
        conn.commit()
        return False

def launchAnalyzer(potentialC2Enrich):
    threads = [Thread(target=urlAnalyze, args=(IOC)) for IOC in potentialC2Enrich]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def main():
    database = "app/webchannels/proxyAnalyzer/database.sqlite3"
    conn = createConnection(database)
    with conn:
        print("[+] Checking potential C2 behavior in proxy logs...")
        potentialC2 = selectPotentialC2(conn)
        print(f"[+] Found {len(potentialC2)} potential C2")
        if not potentialC2:
            exit()
        print(f"[+] Gathering known signatures...")
        potentialC2Enrich = getKnownSignature(conn, potentialC2)
        print(f"[+] Analyzing comportments...")
        launchAnalyzer(potentialC2Enrich)

if __name__ == '__main__':
    main()