const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class Database {
    constructor() {
        this.db = new sqlite3.Database(path.join(__dirname, 'noqeder.db'));
        this.init();
    }

    async init() {
        const queries = [
            `CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                avatar TEXT DEFAULT '',
                bio TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                receiver_id INTEGER,
                content TEXT,
                file_url TEXT,
                file_type TEXT,
                is_read INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            )`
        ];
        for (let q of queries) this.db.run(q);
    }

    // Универсальный метод для получения данных
    get(sql, params = []) {
        return new Promise((res, rej) => this.db.get(sql, params, (err, row) => err ? rej(err) : res(row)));
    }

    all(sql, params = []) {
        return new Promise((res, rej) => this.db.all(sql, params, (err, rows) => err ? rej(err) : res(rows)));
    }

    run(sql, params = []) {
        return new Promise((res, rej) => {
            this.db.run(sql, params, function(err) { err ? rej(err) : res(this.lastID); });
        });
    }
}

module.exports = new Database();
