const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Увеличиваем лимит для файлов
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let messages = [];
let users = [];

io.on('connection', (socket) => {
  console.log('Пользователь подключился:', socket.id);
  socket.emit('history', messages);

  socket.on('new-user', (userData) => {
    users.push({ id: socket.id, ...userData });
    console.log('Новый пользователь:', userData.name);
  });

  socket.on('message', (msgData) => {
    const message = {
      id: Date.now(),
      ...msgData,
      time: new Date().toLocaleTimeString()
    };
    messages.push(message);
    io.emit('message', message);
    console.log('Сообщение от:', msgData.user.name, msgData.type || 'text');
  });

  socket.on('disconnect', () => {
    users = users.filter(u => u.id !== socket.id);
    console.log('Пользователь отключился:', socket.id);
  });
});

const PORT = 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Noqeder с файлами запущен!`);
  console.log(`📱 http://localhost:${PORT}`);
});
