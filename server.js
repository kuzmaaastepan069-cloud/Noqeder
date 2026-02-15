const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const multer = require('multer');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Создаем папки
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Настройка Multer для загрузки файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB лимит
});

// Инициализация базы данных
const db = new sqlite3.Database('./noqeder.db');

// Создаем таблицы
db.serialize(() => {
    // Пользователи
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        name TEXT,
        avatar TEXT,
        bio TEXT,
        music_title TEXT,
        music_artist TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Сообщения
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        text TEXT,
        from_id TEXT,
        to_id TEXT,
        file_name TEXT,
        file_path TEXT,
        file_size INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(from_id) REFERENCES users(id),
        FOREIGN KEY(to_id) REFERENCES users(id)
    )`);

    // Сессии (для онлайн статуса)
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        socket_id TEXT PRIMARY KEY,
        user_id TEXT,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // Индексы для скорости
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`);
});

// Вспомогательные функции
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Б';
    const k = 1024;
    const sizes = ['Б', 'КБ', 'МБ', 'ГБ'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ==================== API ЭНДПОИНТЫ ====================

// Регистрация
app.post('/api/register', async (req, res) => {
    const { username, password, name, avatar, bio, music_title, music_artist } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    try {
        // Проверяем, есть ли уже такой пользователь
        db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (row) {
                return res.status(400).json({ error: 'Username already taken' });
            }

            // Хешируем пароль
            const hashedPassword = await bcrypt.hash(password, 10);
            const userId = 'user_' + Date.now();

            // Сохраняем пользователя
            db.run(
                `INSERT INTO users (id, username, password, name, avatar, bio, music_title, music_artist)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [userId, username, hashedPassword, name || username, avatar || '', bio || '', music_title || '', music_artist || ''],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to create user' });
                    }
                    res.json({ 
                        success: true, 
                        user: {
                            id: userId,
                            username,
                            name: name || username,
                            avatar: avatar || '',
                            bio: bio || '',
                            music: music_title ? { title: music_title, artist: music_artist } : null
                        }
                    });
                }
            );
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Вход
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        try {
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return res.status(401).json({ error: 'Invalid username or password' });
            }

            res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    name: user.name,
                    avatar: user.avatar,
                    bio: user.bio,
                    music: user.music_title ? { title: user.music_title, artist: user.music_artist } : null
                }
            });
        } catch (err) {
            res.status(500).json({ error: 'Server error' });
        }
    });
});

// Загрузка файла
app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    res.json({
        success: true,
        file: {
            name: req.file.originalname,
            path: '/uploads/' + req.file.filename,
            size: req.file.size,
            size_formatted: formatFileSize(req.file.size)
        }
    });
});

// Получить историю сообщений (с пагинацией)
app.get('/api/messages/:userId/:otherId', (req, res) => {
    const { userId, otherId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = 50;
    const offset = (page - 1) * limit;

    db.all(
        `SELECT * FROM messages 
         WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?`,
        [userId, otherId, otherId, userId, limit, offset],
        (err, messages) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json(messages.reverse()); // Переворачиваем для хронологии
        }
    );
});

// ==================== SOCKET.IO ====================

io.on('connection', (socket) => {
    console.log('Подключение:', socket.id);

    // Авторизация через сокет
    socket.on('auth', async (userId) => {
        // Запоминаем сессию
        db.run(
            'INSERT OR REPLACE INTO sessions (socket_id, user_id, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)',
            [socket.id, userId]
        );

        // Отправляем список онлайн пользователей
        db.all(
            'SELECT DISTINCT user_id FROM sessions WHERE last_seen > datetime("now", "-5 minutes")',
            [],
            (err, online) => {
                const onlineUsers = online.map(s => s.user_id);
                io.emit('online-users', onlineUsers);
            }
        );
    });

    // Отправка сообщения
    socket.on('send-message', async (data) => {
        const { from_id, to_id, type, text, file } = data;

        let file_name = null;
        let file_path = null;
        let file_size = null;

        if (file) {
            file_name = file.name;
            file_path = file.path;
            file_size = file.size;
        }

        // Сохраняем в базу
        db.run(
            `INSERT INTO messages (type, text, from_id, to_id, file_name, file_path, file_size)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [type || 'text', text || '', from_id, to_id, file_name, file_path, file_size],
            function(err) {
                if (err) {
                    console.error('Ошибка сохранения:', err);
                    return;
                }

                // Получаем сохраненное сообщение
                db.get(
                    `SELECT m.*, 
                            u_from.name as from_name, u_from.avatar as from_avatar,
                            u_to.name as to_name, u_to.avatar as to_avatar
                     FROM messages m
                     JOIN users u_from ON m.from_id = u_from.id
                     JOIN users u_to ON m.to_id = u_to.id
                     WHERE m.id = ?`,
                    [this.lastID],
                    (err, message) => {
                        if (err) return;

                        // Форматируем для отправки
                        const msg = {
                            id: message.id,
                            type: message.type,
                            text: message.text,
                            time: new Date(message.created_at).toLocaleTimeString(),
                            from: {
                                id: message.from_id,
                                name: message.from_name,
                                avatar: message.from_avatar
                            },
                            to: {
                                id: message.to_id,
                                name: message.to_name,
                                avatar: message.to_avatar
                            }
                        };

                        if (message.file_name) {
                            msg.file = {
                                name: message.file_name,
                                path: message.file_path,
                                size: message.file_size,
                                size_formatted: formatFileSize(message.file_size)
                            };
                        }

                        // Отправляем участникам
                        io.to(socket.id).emit('new-message', msg);
                        
                        // Находим сокет получателя
                        db.get(
                            'SELECT socket_id FROM sessions WHERE user_id = ? AND last_seen > datetime("now", "-5 minutes")',
                            [to_id],
                            (err, session) => {
                                if (session) {
                                    io.to(session.socket_id).emit('new-message', msg);
                                }
                            }
                        );
                    }
                );
            }
        );
    });

    // Загрузка старых сообщений
    socket.on('load-messages', (data) => {
        const { user_id, other_id, page } = data;

        const limit = 50;
        const offset = ((page || 1) - 1) * limit;

        db.all(
            `SELECT m.*, 
                    u_from.name as from_name, u_from.avatar as from_avatar,
                    u_to.name as to_name, u_to.avatar as to_avatar
             FROM messages m
             JOIN users u_from ON m.from_id = u_from.id
             JOIN users u_to ON m.to_id = u_to.id
             WHERE (m.from_id = ? AND m.to_id = ?) OR (m.from_id = ? AND m.to_id = ?)
             ORDER BY m.created_at DESC
             LIMIT ? OFFSET ?`,
            [user_id, other_id, other_id, user_id, limit, offset],
            (err, messages) => {
                if (err) return;

                const formatted = messages.reverse().map(m => ({
                    id: m.id,
                    type: m.type,
                    text: m.text,
                    time: new Date(m.created_at).toLocaleTimeString(),
                    from: {
                        id: m.from_id,
                        name: m.from_name,
                        avatar: m.from_avatar
                    },
                    to: {
                        id: m.to_id,
                        name: m.to_name,
                        avatar: m.to_avatar
                    },
                    file: m.file_name ? {
                        name: m.file_name,
                        path: m.file_path,
                        size: m.file_size,
                        size_formatted: formatFileSize(m.file_size)
                    } : null
                }));

                socket.emit('messages-loaded', formatted);
            }
        );
    });

    // Поиск пользователей
    socket.on('search-users', (query) => {
        db.all(
            'SELECT id, username, name, avatar, bio FROM users WHERE username LIKE ? OR name LIKE ? LIMIT 20',
            [`%${query}%`, `%${query}%`],
            (err, users) => {
                if (err) return;
                socket.emit('search-results', users);
            }
        );
    });

    // Отключение
    socket.on('disconnect', () => {
        db.run('DELETE FROM sessions WHERE socket_id = ?', [socket.id]);

        // Обновляем список онлайн
        db.all(
            'SELECT DISTINCT user_id FROM sessions WHERE last_seen > datetime("now", "-5 minutes")',
            [],
            (err, online) => {
                const onlineUsers = online.map(s => s.user_id);
                io.emit('online-users', onlineUsers);
            }
        );
    });
});

// Очистка старых сессий раз в минуту
setInterval(() => {
    db.run('DELETE FROM sessions WHERE last_seen < datetime("now", "-10 minutes")');
}, 60000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log('\n══════════════════════════════');
    console.log('🚀 Noqeder PRO запущен!');
    console.log(`📱 Порт: ${PORT}`);
    console.log('🗄️ База данных: SQLite');
    console.log('🔐 Хеширование: bcrypt');
    console.log('📦 Файлы: сохраняются на диск');
    console.log('══════════════════════════════\n');
});
