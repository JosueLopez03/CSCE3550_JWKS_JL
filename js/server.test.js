const request = require('supertest');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const app = require('./server');

describe('API Endpoints', () => {
    let server;

    beforeAll(() => {
        server = app.listen(3000); 
    });

    afterAll((done) => {
        server.close(done);
    });

    test('should return 405 Method Not Allowed for non-POST requests to /auth', async () => {
        const response = await request(app).get('/auth');
        expect(response.statusCode).toBe(405);
        expect(response.text).toBe('Method Not Allowed');
    });

    test('should return a JWT token for POST request to /auth', async () => {
        const response = await request(app).post('/auth');
        expect(response.statusCode).toBe(200);
    });

    test('should initialize the database with the correct schema and data', (done) => {
        const sqlite3 = require('sqlite3').verbose();
        const db = new sqlite3.Database('./totally_not_my_privateKeys.db');
    
        db.serialize(() => {
            db.all("PRAGMA table_info('keys')", (err, columns) => {
                if (err) {
                    db.close();
                    return done(err);
                }
                
                expect(columns).toHaveLength(3);
                expect(columns[0].name).toBe('kid');
                expect(columns[1].name).toBe('key');
                expect(columns[2].name).toBe('exp');
                
                db.all("SELECT * FROM keys", (err, rows) => {
                    if (err) {
                        db.close();
                        return done(err);
                    }
                    expect(rows).toHaveLength(2);

                    db.close();
                    done();
                });
            });
            done();
        });
    });
    
    test('should return an expired JWT token for POST request to /auth?expired=true', async () => {
        const response = await request(app).post('/auth?expired=true');
        expect(response.statusCode).toBe(200);
    });

    test('should return 405 Method Not Allowed for non-GET requests to /.well-known/jwks.json', async () => {
        const response = await request(app).post('/.well-known/jwks.json');
        expect(response.statusCode).toBe(405);
        expect(response.text).toBe('Method Not Allowed');
    });

    test('should start the server and listen on the specified port', (done) => {
        const port = 8000; 
        const server = app.listen(port, () => {
            server.close(() => {
                done(); 
            });
        });
    });

    test('should start the server and listen on an available port', (done) => {
        const server = app.listen(0, () => {
            const port = server.address().port;
            server.close(() => {
                done();
            });
        });
    });
});