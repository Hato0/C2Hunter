-- SQLite
DROP TABLE IF EXISTS proxyLogs;
DROP TABLE IF EXISTS ja3Signature;
DROP TABLE IF EXISTS ja3sSignature;
DROP TABLE IF EXISTS jarmSignature;
DROP TABLE IF EXISTS malwareDB;
DROP TABLE IF EXISTS malware_ja3;
DROP TABLE IF EXISTS malware_ja3s;
DROP TABLE IF EXISTS malware_jarm;
DROP TABLE IF EXISTS url_ja3;
DROP TABLE IF EXISTS url_ja3s;
DROP TABLE IF EXISTS url_jarm;

CREATE TABLE proxyLogs (
Id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
URL VARCHAR(250) NOT NULL UNIQUE, 
count INTEGER NOT NULL,
firstSeen VARCHAR(250) NOT NULL, 
lastSeen VARCHAR(250) NOT NULL, 
foHoursSeen INTEGER NOT NULL, 
sourceIP VARCHAR(250) NOT NULL,
isMalicious INT NOT NULL,
isBlacklisted INT NOT NULL,
isWhitelisted INT NOT NULL
);
CREATE TABLE ja3Signature (
Id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
ja3 VARCHAR(250) NOT NULL UNIQUE
);
CREATE TABLE ja3sSignature (
Id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
ja3s VARCHAR(250) NOT NULL UNIQUE
);
CREATE TABLE jarmSignature (
Id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
jarm VARCHAR(250) NOT NULL UNIQUE
);
CREATE TABLE malwareDB (
Id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
name VARCHAR(250) NOT NULL UNIQUE
);
CREATE TABLE malware_jarm (
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
jarmID INTERGER,
malwareID INTERGER,
FOREIGN KEY(malwareID) REFERENCES malwareDB(Id),
FOREIGN KEY(jarmID) REFERENCES jarmSignature(Id)
);
CREATE TABLE malware_ja3 (
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
ja3ID INTERGER,
malwareID INTERGER,
FOREIGN KEY(malwareID) REFERENCES malwareDB(Id),
FOREIGN KEY(ja3ID) REFERENCES ja3Signature(Id)
);
CREATE TABLE malware_ja3s (
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
ja3sID INTERGER,
malwareID INTERGER,
FOREIGN KEY(malwareID) REFERENCES malwareDB(Id),
FOREIGN KEY(ja3sID) REFERENCES ja3sSignature(Id)
);
CREATE TABLE url_ja3s (
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
ja3sID INTERGER,
urlID INTERGER,
FOREIGN KEY(urlID) REFERENCES proxyLogs(Id),
FOREIGN KEY(ja3sID) REFERENCES ja3sSignature(Id)
);
CREATE TABLE url_ja3 (
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
ja3ID INTERGER,
urlID INTERGER,
FOREIGN KEY(urlID) REFERENCES proxyLogs(Id),
FOREIGN KEY(ja3ID) REFERENCES ja3Signature(Id)
);
CREATE TABLE url_jarm (
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
jarmID INTERGER,
urlID INTERGER,
FOREIGN KEY(urlID) REFERENCES proxyLogs(Id),
FOREIGN KEY(jarmID) REFERENCES jarmSignature(Id)
);