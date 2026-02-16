const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const db = require('./database');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const JWT_SECRET = 'NOQEDER_ULTRA_SECRET_2025';
const SALT_ROUNDS = 12;

app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Настройка загрузки файлов
const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// --- AUTH API ---
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        const userId = await db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash]);
        const token = jwt.sign({ id: userId, username }, JWT_SECRET);
        res.json({ token, user: { id: userId, username } });
    } catch (e) { res.status(400).json({ error: 'Имя занято' }); }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user.id, username }, JWT_SECRET);
        res.json({ token, user: { id: user.id, username, bio: user.bio } });
    } else { res.status(401).json({ error: 'Ошибка входа' }); }
});

app.post('/api/upload', upload.single('file'), (req, res) => {
    res.json({ url: `/uploads/${req.file.filename}`, type: req.file.mimetype });
});

// --- SOCKETS (REAL-TIME) ---
const onlineUsers = new Map(); // userId -> socketId

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return next(new Error('Auth error'));
        socket.user = decoded;
        next();
    });
});

io.on('connection', (socket) => {
    const myId = socket.user.id;
    onlineUsers.set(myId, socket.id);
    io.emit('online-update', Array.from(onlineUsers.keys()));

    socket.on('load-history', async (partnerId) => {
        const history = await db.all(`
            SELECT * FROM messages 
            WHERE (sender_id = ? AND receiver_id = ?) 
            OR (sender_id = ? AND receiver_id = ?)
            ORDER BY created_at ASC`, [myId, partnerId, partnerId, myId]);
        socket.emit('history', history);
    });

    socket.on('send-msg', async (data) => {
        const { toId, text, fileUrl, fileType } = data;
        const msgId = await db.run(
            'INSERT INTO messages (sender_id, receiver_id, content, file_url, file_type) VALUES (?, ?, ?, ?, ?)',
            [myId, toId, text, fileUrl, fileType]
        );
        const message = { id: msgId, sender_id: myId, content: text, file_url: fileUrl, file_type: fileType };
        
        const targetSocket = onlineUsers.get(toId);
        if (targetSocket) io.to(targetSocket).emit('new-msg', message);
        socket.emit('msg-delivered', message);
    });

    socket.on('disconnect', () => {
        onlineUsers.delete(myId);
        io.emit('online-update', Array.from(onlineUsers.keys()));
    });
});

server.listen(3000, () => console.log('🚀 Noqeder ИДЕАЛЬНЫЙ запущен на порту 3000'));
