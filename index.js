#!/usr/bin/env node

const cors = require('cors');
const path = require('path');
const chalk = require('chalk');
const express = require('express');

const { generateTOTP, generateHOTP } = require('./lib/2fa');

const PORT = process.env.PORT || 3000;
const app = express();

app.enable('trust proxy');
app.set('json spaces', 2);

app.use(cors());
app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/totp', (req, res) => {
    const { secret } = req.body;
    if (!secret) {
        return res.status(400).json({ status: false, message: 'Secret key is required!' });
    }
    const clean = secret.toUpperCase().replace(/\s+/g, '');
    if (clean.length < 16) {
        return res.status(400).json({ status: false, message: 'Secret key must be at least 16 characters!' });
    }
    try {
        const result = generateTOTP(clean);
        return res.json({ status: true, data: result });
    } catch (e) {
        return res.status(400).json({ status: false, message: 'Invalid secret key format!' });
    }
});

app.post('/api/hotp', (req, res) => {
    const { secret, counter } = req.body;
    if (!secret) {
        return res.status(400).json({ status: false, message: 'Secret key is required!' });
    }
    const clean = secret.toUpperCase().replace(/\s+/g, '');
    if (clean.length < 16) {
        return res.status(400).json({ status: false, message: 'Secret key must be at least 16 characters!' });
    }
    const counterVal = parseInt(counter);
    if (isNaN(counterVal) || counterVal < 0) {
        return res.status(400).json({ status: false, message: 'Counter must be a non-negative integer!' });
    }
    try {
        const result = generateHOTP(clean, counterVal);
        return res.json({ status: true, data: result });
    } catch (e) {
        return res.status(400).json({ status: false, message: 'Invalid secret key format!' });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(chalk.green(`Server running on http://localhost:${PORT}`));
});
