const express = require('express');
const crypto = require('crypto');
const FLAG = process.env.FLAG || 'flag{this_is_a_fake_flag}';

const app = express();
app.use(express.urlencoded({ extended: true }));

const USER_DB = {
    user: {
        username: 'user', 
        password: crypto.randomBytes(32).toString('hex')
    },
    guest: {
        username: 'guest',
        password: 'guest'
    }
};

app.get('/', (req, res) => {
    res.send(`
    <html><head><title>Login</title><link rel="stylesheet" href="https://cdn.simplecss.org/simple.min.css"></head>
    <body>
    <section>
    <h1>Login</h1>
    <form action="/login" method="post">
    <input type="text" name="username" placeholder="Username" length="6" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Login</button>
    </form>
    </section>
    </body></html>
    `);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username.length > 6) return res.send('Username is too long');

    const user = USER_DB[username];
    if (user && user.password == password) {
        if (username === 'guest') {
            res.send('Welcome, guest. You do not have permission to view the flag');
        } else {
            res.send(`Welcome, ${username}. Here is your flag: ${FLAG}`);
        }
    } else {
        res.send('Invalid username or password');
    }
});

app.listen(5000, () => {
    console.log('Server is running on port 5000');
});