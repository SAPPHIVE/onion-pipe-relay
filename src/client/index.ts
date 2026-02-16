import express, { Request, Response } from 'express';
import axios from 'axios';
import pino from 'pino';
import fs from 'fs';
import path from 'path';
import { CryptoService } from '../common/crypto';

const logger = pino({ name: 'LOOHIVE-Client' });
const app = express();
app.use(express.json());

const KEY_PATH = process.env.PRIVATE_KEY_PATH || '/keys/keys.json';

/**
 * Define SERVICES_MAP from process.env.SERVICES_MAP
 * Expected format: "/api=http://app:3000,/=http://web:8080"
 * Defaults to TARGET_URL or localhost if not provided.
 */
const SERVICES_MAP: Record<string, string> = process.env.SERVICES_MAP
    ? Object.fromEntries(process.env.SERVICES_MAP.split(',').map(pair => {
        const [pathPrefix, url] = pair.split('=');
        return [pathPrefix, url];
    }))
    : { '/': process.env.TARGET_URL || 'http://localhost:8080' };

/**
 * Longest prefix match for multiplexing
 */
function getTarget(requestPath: string): string {
    const sortedPaths = Object.keys(SERVICES_MAP).sort((a, b) => b.length - a.length);
    for (const p of sortedPaths) {
        if (requestPath.startsWith(p)) {
            return SERVICES_MAP[p];
        }
    }
    return SERVICES_MAP['/'] || Object.values(SERVICES_MAP)[0];
}

async function getKeys() {
    if (fs.existsSync(KEY_PATH)) return JSON.parse(fs.readFileSync(KEY_PATH, 'utf8'));
    const keys = await CryptoService.generateKeyPair();
    fs.writeFileSync(KEY_PATH, JSON.stringify(keys));
    return keys;
}

app.post('/webhook', async (req, res) => {
    try {
        const keys = await getKeys();
        const decryptedRaw = await CryptoService.decrypt(req.body.payload, keys.publicKey, keys.privateKey);
        const decrypted = JSON.parse(decryptedRaw);

        const path = decrypted.path || '/';
        const targetUrl = getTarget(path);

        // Sync Full Tunnel Request Handling (New Mode)
        if (decrypted.method && decrypted.requestId) {
            logger.info({ 
                method: decrypted.method, 
                path: path, 
                requestId: decrypted.requestId,
                target: targetUrl 
            }, '[LOOHIVE] Proxying tunnel request');
            
            // Handle headers: strip hop-by-hop and set correct host
            const headers = { ...decrypted.headers };
            delete headers['host'];
            delete headers['content-length'];
            delete headers['connection'];

            const result = await axios({
                method: decrypted.method,
                url: targetUrl.replace(/\/$/, '') + path,
                data: decrypted.body,
                headers: { 
                    ...headers, 
                    'host': new URL(targetUrl).host,
                    'x-onion-relay': 'true'
                },
                validateStatus: () => true // Forward all statuses (200, 404, 500, etc)
            });

            return res.status(result.status).json(result.data);
        }

        // Legacy Webhook Handling (Old Mode)
        const { data, timestamp } = decrypted;
        if (Date.now() - timestamp > 60000) return res.status(403).send('Expired');

        logger.info({ target: targetUrl }, '[LOOHIVE] Forwarding legacy webhook to target app');
        const response = await axios.post(targetUrl, data);
        res.status(response.status).send(response.data);
    } catch (e: any) {
        logger.error({ error: e.message }, '[LOOHIVE] Client bypass failure');
        res.status(502).json({ error: 'LOCAL_PROXY_ERROR', details: e.message });
    }
});

app.listen(80, async () => {
    const keys = await getKeys();
    logger.info(`[LOOHIVE] Onion Client ready. Public Key: ${keys.publicKey}`);
});
