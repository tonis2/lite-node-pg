import PGdriver from "./driver.mjs";
import fs from "fs"

const db = new PGdriver();

const config = {
    "host": "localhost",
    "port": 26257,
    "user": "root",
    "password": "root",
    "database": "defaultdb",
    "tls": {
        host: "localhost",
        port: 26257,
        key: fs.readFileSync('certs/client.root.key'),
        cert: fs.readFileSync('certs/client.root.crt'),
        ca: fs.readFileSync('certs/ca.crt')
    }
};

db.connect(config, (err, res) => {
    if (err) {
        console.log("connection error.");
        return;
    }
    console.log(res); // connected
});

db.query("CREATE IF NOT EXISTS database root;", (res) => { })

db.query("use root;", (res) => { })

db.query("CREATE TABLE IF NOT EXISTS users (id INT, name TEXT, age INT);", (res) => { })

db.query("INSERT INTO users (id, name, age) VALUES (1, 'TOM', 23);", (err, res) => { })
db.query("INSERT INTO users (id, name, age) VALUES (2, 'TEST', 11);", (err, res) => { })

db.query("select * from users", (err, res) => {
    console.log(res)
    if (err) {
        console.log("error occurred during query.");
        return;
    }
});

db.query("DROP TABLE users;", () => {
    db.close()
})