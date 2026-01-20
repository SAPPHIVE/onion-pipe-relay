import express, { Request, Response, NextFunction } from 'express';
import WebSocket, { WebSocketServer } from 'ws';
import { RedisService } from '../common/redis';
import { CryptoService } from '../common/crypto';
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';
import * as http from 'http';

const logger = pino({ name: 'EntryRelay', transport: { target: 'pino-pretty' }, level: process.env.LOG_LEVEL || 'info' });
const app = express();
app.use(express.json());

const redis = new RedisService(process.env.REDIS_URL);
const bridgeConnections = new Map<string, WebSocket>();
const PORT = process.env.PORT || 3000;

// --- MASTER MODE CONFIG ---
const IS_MASTER = process.env.MASTER === 'true';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin'; // Should be changed in production

const bodyLogger = (req: Request, res: Response, next: NextFunction) => {
    if (IS_MASTER) logger.debug({ path: req.path }, 'Request received');
    next();
};

app.use(bodyLogger);

// --- DASHBOARD ROUTES (MASTER ONLY) ---
if (IS_MASTER) {
    logger.info('👑 Master Mode Enabled: Dashboard active at /dashboard');
    
    app.get('/dashboard', (req, res) => {
    // Basic Auth Check
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Basic ')) {
        res.setHeader('WWW-Authenticate', 'Basic realm="Onion-Pipe Dashboard"');
        return res.status(401).send('Authentication required');
    }
    
    try {
        const base64 = auth.split(' ')[1];
        if (!base64) throw new Error();
        const [user, pwd] = Buffer.from(base64, 'base64').toString().split(':');
        if (pwd !== ADMIN_PASSWORD) {
            return res.status(403).send('Invalid password');
        }
    } catch {
        return res.status(400).send('Invalid Authorization header');
    }

    // Simple placeholder for dashboard
    res.send(`
        <html>
        <head><title>Onion-Pipe Master Controller</title></head>
        <body style="font-family: sans-serif; padding: 20px;">
            <h1>🧅 Onion-Pipe Masternode Dashboard</h1>
            <div style="border: 1px solid #ccc; padding: 15px; border-radius: 8px;">
                <p><strong>Status:</strong> <span style="color: green;">Online</span></p>
                <p><strong>Active Bridges:</strong> ${bridgeConnections.size}</p>
                <p><strong>Mode:</strong> Master Controller</p>
            </div>
            <h2>Connected Bridges</h2>
            <pre id="nodes">Loading...</pre>
            <script>
                fetch('/dashboard/nodes', { headers: { 'Authorization': '${auth}' } })
                    .then(r => r.json())
                    .then(data => document.getElementById('nodes').innerText = JSON.stringify(data, null, 2));
            </script>
        </body>
        </html>
    `);
});

app.get('/dashboard/nodes', async (req, res) => {
    // Basic Auth Check
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).end();

    const bridges = await redis.getHealthyBridges();
    res.json(bridges);
});
}

app.get('/health', (req, res) => res.status(200).send('OK'));

const wss = new WebSocketServer({ noServer: true });

wss.on('connection', (ws, req) => {
    const bridgeId = uuidv4();
    logger.info({ bridgeId }, 'Bridge connected');
    bridgeConnections.set(bridgeId, ws);

    ws.on('message', async (data) => {
        try {
            const msg = JSON.parse(data.toString());
            if (msg.type === 'heartbeat') {
                await redis.updateBridgeHeartbeat({
                    bridge_id: bridgeId,
                    load: msg.load || 0,
                    uptime: msg.uptime || 0,
                    last_seen: Date.now()
                });
            }
        } catch (e) { /* ignore malformed heartbeat */ }
    });

    ws.on('close', () => {
        logger.warn({ bridgeId }, 'Bridge disconnected');
        bridgeConnections.delete(bridgeId);
    });
});

app.post('/register', async (req, res) => {
    const { onion_service_id, public_key, registration_secret } = req.body;

    // If in Master mode, we might want to restrict who can register
    if (IS_MASTER && process.env.REGISTRATION_SECRET) {
        if (registration_secret !== process.env.REGISTRATION_SECRET) {
            return res.status(403).json({ error: 'Unauthorized registration' });
        }
    }

    const token = uuidv4();
    await redis.setTokenMetadata(token, {
        onion_service_id,
        public_key,
        status: 'active',
        created_at: Math.floor(Date.now() / 1000).toString()
    });

    logger.info({ token, onion_service_id }, 'New client registered');
    res.json({ 
        token,
        relay_url: process.env.PUBLIC_RELAY_URL || `http://localhost:${PORT}`
    });
});

app.post('/h/:token', async (req, res) => {
    const { token } = req.params;
    try {
        const metadata = await redis.getTokenMetadata(token);
        if (!metadata || metadata.status !== 'active') return res.status(404).end();

        const encrypted = await CryptoService.encrypt(JSON.stringify({
            data: req.body,
            timestamp: Date.now(),
            nonce: uuidv4()
        }), metadata.public_key);

        const healthyBridges = await redis.getHealthyBridges();
        const activeIds = healthyBridges.map(b => b.bridge_id).filter(id => bridgeConnections.has(id));

        if (activeIds.length === 0) return res.status(503).json({ error: 'No bridges' });

        const selectedId = activeIds[Math.floor(Math.random() * activeIds.length)];
        const ws = bridgeConnections.get(selectedId);
        
        ws?.send(JSON.stringify({
            type: 'dispatch',
            onion_service_id: metadata.onion_service_id,
            payload: encrypted
        }));

        res.status(202).json({ status: 'dispatched' });
    } catch (err) {
        res.status(500).end();
    }
});

const server = app.listen(PORT, async () => {
    await redis.connect();
    logger.info(`Relay running on ${PORT}`);
});

server.on('upgrade', (request: http.IncomingMessage, socket: any, head: Buffer) => {
    wss.handleUpgrade(request, socket, head, (ws) => wss.emit('connection', ws, request));
});
