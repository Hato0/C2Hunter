-- SQLite
DROP TABLE proxyLogs;
CREATE TABLE proxyLogs (
Id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
URL VARCHAR(250) NOT NULL, 
count INTEGER NOT NULL,
firstSeen VARCHAR(250) NOT NULL, 
lastSeen VARCHAR(250) NOT NULL, 
foHoursSeen INTEGER NOT NULL, 
sourceIP VARCHAR(250) NOT NULL, 
JA3 VARCHAR(128), 
JA3S VARCHAR(128), 
JARM VARCHAR(62)
);