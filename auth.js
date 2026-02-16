// Пример функции входа на клиенте
async function login(username, password) {
    const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    
    if (data.token) {
        localStorage.setItem('noqeder_token', data.token);
        localStorage.setItem('user_info', JSON.stringify(data.user));
        initSocket(data.token); // Подключение к сокетам с токеном
    }
}

function initSocket(token) {
    const socket = io({ auth: { token } });
    // ... обработка событий сокета
}
