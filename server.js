const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Логирование
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
}

function log(type, data) {
    const date = new Date();
    const logFile = path.join(logsDir, `${date.toISOString().split('T')[0]}.txt`);
    const time = date.toLocaleTimeString();
    const entry = `[${time}] ${type}: ${JSON.stringify(data)}\n`;
    
    fs.appendFile(logFile, entry, (err) => {
        if (err) console.error('Ошибка лога:', err);
    });
    console.log(entry.trim());
}

// Хранилища
let users = [];
let messages = [];
const messageSet = new Set(); // Для защиты от дублей

io.on('connection', (socket) => {
    log('ПОДКЛЮЧЕНИЕ', { socketId: socket.id });
    
    // Отправляем историю только этому пользователю
    socket.emit('history', messages);

    // Новый пользователь
    socket.on('new-user', (userData) => {
        // Проверяем уникальность username
        const existingUser = users.find(u => u.username === userData.username);
        if (existingUser) {
            socket.emit('username-taken');
            return;
        }
        
        const user = {
            id: socket.id,
            ...userData,
            online: true,
            joinedAt: new Date().toLocaleTimeString()
        };
        users.push(user);
        
        log('НОВЫЙ ПОЛЬЗОВАТЕЛЬ', { username: userData.username });
        
        // Отправляем обновленный список всем
        io.emit('users', users);
        
        // Уведомление только для других
        socket.broadcast.emit('system-message', `${userData.name} присоединился`);
    });

    // Обновление профиля
    socket.on('update-profile', (userData) => {
        const index = users.findIndex(u => u.id === socket.id);
        if (index !== -1) {
            users[index] = { ...users[index], ...userData };
            io.emit('users', users);
        }
    });

    // Публичное сообщение
    socket.on('message', (msgData) => {
        // Защита от дублей
        const msgKey = `${socket.id}_${msgData.text}_${Date.now()}`;
        if (messageSet.has(msgKey)) return;
        messageSet.add(msgKey);
        
        // Очистка старых ключей
        if (messageSet.size > 1000) {
            const toDelete = Array.from(messageSet).slice(0, 500);
            toDelete.forEach(key => messageSet.delete(key));
        }

        const message = {
            id: Date.now(),
            type: 'public',
            text: msgData.text,
            user: msgData.user,
            time: new Date().toLocaleTimeString()
        };
        
        messages.push(message);
        log('СООБЩЕНИЕ', { от: msgData.user.name, текст: msgData.text });
        
        // Отправляем всем
        io.emit('message', message);
    });

    // Личное сообщение
    socket.on('private-message', (msgData) => {
        // Защита от дублей
        const msgKey = `${socket.id}_${msgData.to.id}_${msgData.text}_${Date.now()}`;
        if (messageSet.has(msgKey)) return;
        messageSet.add(msgKey);

        const message = {
            id: Date.now(),
            type: 'private',
            text: msgData.text,
            from: msgData.from,
            to: msgData.to,
            time: new Date().toLocaleTimeString()
        };
        
        messages.push(message);
        
        log('ЛИЧНОЕ СООБЩЕНИЕ', {
            от: msgData.from.username,
            кому: msgData.to.username
        });
        
        // Отправляем только участникам
        io.to(msgData.from.id).emit('private-message', message);
        io.to(msgData.to.id).emit('private-message', message);
    });

    // Отключение
    socket.on('disconnect', () => {
        const user = users.find(u => u.id === socket.id);
        users = users.filter(u => u.id !== socket.id);
        
        if (user) {
            log('ОТКЛЮЧЕНИЕ', { username: user.username });
            io.emit('users', users);
            socket.broadcast.emit('system-message', `${user.name} покинул`);
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log('\n══════════════════════════════');
    console.log('🚀 Noqeder запущен!');
    console.log(`📱 Порт: ${PORT}`);
    console.log('📁 Логи в /logs');
    console.log('══════════════════════════════\n');
});
