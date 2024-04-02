const express = require('express');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const argon2 = require('argon2');
const crypto = require('crypto');

const app = express();
const port = 8080;

let db;
let encryptionKey;

encryptionKey = process.env.NOT_MY_KEY; // Retrieve encryption key from environment variable
if (!encryptionKey) {
    console.error('Encryption key not found in environment variable NOT_MY_KEY');
    process.exit(1);
}

async function initializeDatabase() {
    db = new sqlite3.Database('./database.db');
    db.run(`CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,  
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
}

async function generatePassword() {
    return uuidv4();
}

async function hashPassword(password) {
    return await argon2.hash(password);
}

function encryptKeyPair(key) {
    const algorithm = 'aes-256-cbc';
    const iv = crypto.randomBytes(16); // Initialization vector

    // Create a cipher object
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(encryptionKey, 'hex'), iv);

    // Encrypt the key
    let encrypted = cipher.update(key, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Return the encrypted key along with the initialization vector
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted
    };
}

function decryptKeyPair(encryptedKey) {
    const algorithm = 'aes-256-cbc';
    const iv = Buffer.from(encryptedKey.iv, 'hex');

    // Create a decipher object
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(encryptionKey, 'hex'), iv);

    // Decrypt the encrypted key
    let decrypted = decipher.update(encryptedKey.encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // Return the decrypted key
    return decrypted;
}

app.use(express.json());

app.post('/register', async (req, res) => {
    const { username, email } = req.body;
    
    try {
        // Generate secure password
        const password = await generatePassword();

        // Hash the password
        const hashedPassword = await hashPassword(password);

        // Encrypt user data
        const encryptedUsername = encryptKeyPair(username);
        const encryptedEmail = encryptKeyPair(email);

        // Store encrypted user details and hashed password in the database
        db.run(`INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`, [encryptedUsername, hashedPassword, encryptedEmail], function(err) {
            if (err) {
                console.error(err.message);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            console.log(`User ${username} registered with email ${email}`);
            // Return the status code and generated password
            return res.status(200).json({ password });
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/auth', async (req, res) => {
    const { username, password } = req.body;
    const requestIp = req.ip;

    try {
        // Decrypt user data
        const decryptedUsername = decryptKeyPair(username);
        // Assuming you're storing the encrypted password_hash and email in the database, you'll need to decrypt them here as well

        // Retrieve user from database using decrypted username
        const user = await getUserByUsername(decryptedUsername);
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Verify password
        const isValidPassword = await argon2.verify(user.password_hash, password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Log authentication request
        logAuthenticationRequest(requestIp, user.id);

        // Respond with success
        return res.status(200).json({ message: 'Authentication successful' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

async function getUserByUsername(username) {
    return new Promise((resolve, reject) => {
        // Decrypt the username before querying the database
        const decryptedUsername = decryptKeyPair(username);
        db.get('SELECT * FROM users WHERE username = ?', [decryptedUsername], (err, row) => {
            if (err) {
                return reject(err);
            }
            resolve(row);
        });
    });
}

async function logAuthenticationRequest(requestIp, userId) {
    db.run(`INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)`, [requestIp, userId], function(err) {
        if (err) {
            console.error('Error logging authentication request:', err.message);
        }
        console.log('Authentication request logged:', this.lastID);
    });
}

initializeDatabase().then(() => {
    app.listen(port, () => {
        console.log(`Server is running on port ${port}`);
    });
});

module.exports = app;
