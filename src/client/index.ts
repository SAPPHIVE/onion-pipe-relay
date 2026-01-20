import express, { Request, Response } from 'express';
import axios from 'axios';
import pino from 'pino';
import fs from 'fs';
import path from 'path';
import { CryptoService } from '../common/crypto';

const logger = pino({ name: 'OnionClient' });
const app = express();
app.use(express.json());

const KEY_PATH = process.env.PRIVATE_KEY_PATH || '/keys/keys.json';
const TARGET_URL = process.env.TARGET_URL || 'http://localhost:8080';

async function getKeys() {
    if (fs.existsSync(KEY_PATH)) return JSON.parse(fs.readFileSync(KEY_PATH, 'utf8'));
    const keys = await CryptoService.generateKeyPair();
    fs.writeFileSync(KEY_PATH, JSON.stringify(keys));
    return keys;
}

app.post('/webhook', async (req, res) => {
    try {
        const keys = await getKeys();
        const decrypted = await CryptoService.decrypt(req.body.payload, keys.publicKey, keys.privateKey);
        const { data, timestamp } = JSON.parse(decrypted);

        if (Date.now() - timestamp > 60000) return res.status(403).send('Expired');

        logger.info('Forwarding to target app');
        await axios.post(TARGET_URL, data);
        res.status(200).send('OK');
    } catch (e) {
        res.status(400).send('Fail');
    }
});

app.listen(80, async () => {
    const keys = await getKeys();
    logger.info(`Onion Client ready. Public Key: ${keys.publicKey}`);
});
