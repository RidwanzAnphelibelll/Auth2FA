#!/usr/bin/env node

const cors = require('cors');
const path = require('path');
const chalk = require('chalk');
const express = require('express');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const app = express();

app.enable('trust proxy');
app.set('json spaces', 2);

app.use(cors());
app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));

const base32Decode = (base32) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = base32.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
    let bits = '';
    for (const char of clean) {
        const val = chars.indexOf(char);
        if (val === -1) throw new Error('Invalid base32 character: ' + char);
        bits += val.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return Buffer.from(bytes);
};

const generateTOTP = (secret, period = 30, digits = 6) => {
    const now = Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / period);
    const timeRemaining = period - (now % period);
    const key = base32Decode(secret);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigInt64BE(BigInt(counter));
    const hmac = crypto.createHmac('sha1', key);
    hmac.update(counterBuffer);
    const hash = hmac.digest();
    const offset = hash[hash.length - 1] & 0x0f;
    const code = (
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff)
    ) % Math.pow(10, digits);
    return {
        token: code.toString().padStart(digits, '0'),
        timeRemaining,
        period
    };
};

app.post('/api/totp', (req, res) => {
    const { secret } = req.body;
    if (!secret) {
        return res.status(400).json({ status: false, message: 'Secret key is required!' });
    }
    try {
        const result = generateTOTP(secret.toUpperCase().replace(/\s+/g, ''));
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
