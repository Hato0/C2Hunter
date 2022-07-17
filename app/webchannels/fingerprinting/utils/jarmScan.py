import asyncio
from jarm.scanner.scanner import Scanner
import logging

class JARMScan(object):
    def __init__(self, IOC):
        self.url=IOC.split(':')[0]
        self.port=IOC.split(':')[1]

    def generateJARM(self):
        logging.getLogger('asyncio').setLevel(logging.CRITICAL)
        JARM = []
        for i in range(3):
            JARM.append(Scanner.scan(self.url, self.port, timeout=5, suppress=True))
        if len(set(JARM)) == 1:
            return JARM[0]
        else:
            return False