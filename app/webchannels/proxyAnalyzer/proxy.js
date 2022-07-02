const net = require("net");
const server = net.createServer();
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('app/webchannels/proxyAnalyzer/database.sqlite3');

server.on("connection", (clientToProxySocket) => {
    console.log("Client connected to proxy");
    var clientIP = clientToProxySocket.remoteAddress;
    clientToProxySocket.once("data", (data) => {
        let isTLSConnection = data.toString().indexOf("CONNECT") !== -1;
        let datetime = new Date();
        let serverPort = 80;
        let serverAddress;
        let re = new RegExp('\\s+(\\d{2}):');
        console.log(data.toString());
        db.all("SELECT * FROM proxyLogs where URL='"+ data.toString().split("Host: ")[1].split("\r\n")[0] + "'", (err, rows) => {
            if (err) {
              console.log(err);
            }
            if (rows.length != 0){
                rows.forEach((row) => {
                    let foHoursSeen;
                    let logCount;
                    if (row.foHoursSeen != 0){
                        let lastHourCut = row.lastSeen.match(re);
                        let currentHour = datetime.getHours();
                        if (currentHour != lastHourCut[1]){
                            foHoursSeen = row.foHoursSeen+1;
                        } else {
                            foHoursSeen = row.foHoursSeen;
                        }
                    } else {
                        foHoursSeen = 1;
                    }
                    logCount = row.count+1;
                    db.run("UPDATE proxyLogs SET count = " + logCount + ", lastSeen = '" + datetime + "' , foHoursSeen = " + foHoursSeen + " WHERE URL = '" + row.URL + "';" , function(err) {
                        if (err) {
                            return console.log(err.message);
                        }
                    });
                });
            } else {
                db.run("INSERT INTO proxyLogs (URL, count, firstSeen, lastSeen, foHoursSeen, sourceIP, isMalicious) VALUES ('" 
                + data.toString().split("Host: ")[1].split("\r\n")[0] + "', 1, '" + datetime + "', '" + datetime + "', 1, '" + clientIP + "', 0)"
                , function(err) {
                    if (err) {
                        return console.log(err.message);
                    }
                });
            }
        });
        db.all("SELECT * FROM proxyLogs where URL = '"+ data.toString().split("Host: ")[1].split("\r\n")[0] + "' and isMalicious = 1", (err, rows) => {
            if (err) {
              console.log(err);
            }
            if (rows.length == 0){
                if (isTLSConnection) {
                    serverPort = 443;
                    serverAddress = data
                        .toString()
                        .split("CONNECT")[1]
                        .split(" ")[1]
                        .split(":")[0];
                } else {
                    serverAddress = data.toString().split("Host: ")[1].split("\r\n")[0];
                }
                console.log(serverAddress);

                let proxyToServerSocket = net.createConnection(
                    {
                        host: serverAddress,
                        port: serverPort,
                    },
                    () => {
                        console.log("Proxy to server set up");
                    }
                );


                if (isTLSConnection) {
                    clientToProxySocket.write("HTTP/1.1 200 OK\r\n\r\n");
                } else {
                    proxyToServerSocket.write(data);
                }

                clientToProxySocket.pipe(proxyToServerSocket);
                proxyToServerSocket.pipe(clientToProxySocket);

                proxyToServerSocket.on("error", (err) => {
                    console.log("Proxy to server error");
                    console.log(err);
                });

                clientToProxySocket.on("error", (err) => {
                    console.log("Client to proxy error");
                    console.log(err)
                });
            }
        });
    });
});

server.on("error", (err) => {
    console.log("Some internal server error occurred");
    console.log(err);
});

server.on("close", () => {
    console.log("Client disconnected");
});

server.listen(
    {
        host: "0.0.0.0",
        port: 8080,
    },
    () => {
        console.log("Server listening on 0.0.0.0:8080");
    }
);
