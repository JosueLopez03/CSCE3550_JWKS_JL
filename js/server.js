const express = require('express');
const jose = require('node-jose');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const argon2 = require('argon2');
const crypto = require('crypto');
const dotenv = require('dotenv').config();

const app = express();
const port = 8080;

const db = new sqlite3.Database('totally_not_my_privateKeys.db');

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;


// Use the environment variable NOT_MY_KEY for AES encryption and decryption
const aesKey = process.env.NOT_MY_KEY || 'defaultkey' // Provide a default key if NOT_MY_KEY is not set

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
}


function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid
    }
  };

   token = jwt.sign(payload, keyPair.toPEM(true), options);
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };
  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
}

// Function to generate a secure password using UUIDv4
function generateSecurePassword() {
  // Generate a UUIDv4 as a secure password
  const generatedPassword = uuidv4();

  // Return the password in JSON format
  return { password: generatedPassword };
}

// Encrypt private key using AES encryption
function encryptPrivateKey(privateKey) {
  let cipher = crypto.createCipheriv('aes-256-cbc', 'bf3c199c2470cb477d907b1e0917c17b', "5183666c72eec9e4");
  let encryptedKey = cipher.update(privateKey, 'utf8', 'base64');
  encryptedKey += cipher.final('base64');
  return encryptedKey;
}

// Decrypt private key using AES decryption
function decryptPrivateKey(encryptedKey) {
  let decipher = crypto.createDecipheriv('aes-256-cbc', 'bf3c199c2470cb477d907b1e0917c17b', "5183666c72eec9e4");
  let decryptedKey = decipher.update(encryptedKey, 'base64', 'utf8');
  decryptedKey += decipher.final('utf8');
  return decryptedKey;
}

// database operations
function Database() {
  let db = new sqlite3.Database('./totally_not_my_privateKeys.db'); // create database file
  db.run('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT,key BLOB NOT NULL,exp INTEGER NOT NULL)'); // create keys table
  db.run('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,email TEXT UNIQUE,date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,last_login TIMESTAMP)'); //create users table
  db.run('CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,request_ip TEXT NOT NULL,request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,user_id INTEGER,  FOREIGN KEY(user_id) REFERENCES users(id));')

  // Encrypt private keys before inserting into the database
  db.run('INSERT INTO keys(key, exp) VALUES(?, ?)', [encryptPrivateKey(keyPair.toPEM(true)), Math.floor(Date.now() / 1000) + 3600]);
  db.run('INSERT INTO keys(key, exp) VALUES(?, ?)', [encryptPrivateKey(expiredKeyPair.toPEM(true)), Math.floor(Date.now() / 1000) - 3600]);
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
  const validKeys = [keyPair].filter(key => !key.expired);
  res.setHeader('Content-Type', 'application/json');
  res.json({ keys: validKeys.map(key => key.toJSON()) });
});

app.use(express.json());
app.post('/auth', async (req, res) => {
  try {
    const requestIp = req.ip;
    const requestTimestamp = new Date().toISOString();
    const { username } = req.body;
    const getUserIdQuery = 'SELECT id FROM users WHERE username = ?';

    // Wrap the entire logic in an async function
    const getUserId = async () => {
      return new Promise((resolve, reject) => {
        db.get(getUserIdQuery, [username], (error, row) => {
          if (error) {
            reject(error);
          } else {
            resolve(row ? row.id : null);
          }
        });
      });
    };

    try {
      const userId = await getUserId();

      if (!userId) {
        res.status(404).send('User not found');
        return;
      }

      const insertAuthLogQuery = 'INSERT INTO auth_logs(request_ip, request_timestamp, user_id) VALUES (?, ?, ?)';
      await new Promise((resolve, reject) => {
        db.run(insertAuthLogQuery, [requestIp, requestTimestamp, userId], (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });

      if (req.query.expired === 'true') {
        res.send(expiredToken);
      } else {
        res.send(token);
      }

    } catch (error) {
      console.error('Error during authentication:', error);
      res.status(500).send('Internal Server Error');
    }
  } catch (error) {
    console.error('Error during authentication:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.use(express.json());
app.post('/register', async (req, res) => {
  try {
    const { username, email } = req.body;
    const generatedPassword = generateSecurePassword();

    try {
      const hashedPassword = await argon2.hash(generatedPassword.password);
      const insertUserQuery = 'INSERT INTO users(username, email, password_hash) VALUES (?, ?, ?)';
      await new Promise((resolve, reject) => {
        db.run(insertUserQuery, [username, email, hashedPassword], (error) => {
          if (error) {
            if (error.message.includes('UNIQUE constraint failed')) {
              res.status(400).send('Username or email is already taken.');
            } else {
              reject(error);
            }
          } else {
            res.status(201).json({ password: generatedPassword.password });
            resolve();
          }
        });
      });
    } catch (error) {
      console.error('Error during password hashing or user registration:', error);
      res.status(500).send('Internal Server Error');
    }
  } catch (error) {
    console.error('Error during user registration:', error);
    res.status(500).send('Internal Server Error');
  }
});

generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  const db = new sqlite3.Database('./totally_not_my_privateKeys.db');
  Database()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});

module.exports = app;
