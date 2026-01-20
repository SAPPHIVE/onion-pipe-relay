import WebSocket from 'ws';
import { SocksProxyAgent } from 'socks-proxy-agent';
import axios from 'axios';
import pino from 'pino';

const logger = pino({ name: 'BridgeRelay', transport: { target: 'pino-pretty' } });
const RELAY_WS_URL = process.env.RELAY_URL || 'ws://relay:3000';
const TOR_SOCKS = process.env.TOR_SOCKS || 'socks5h://tor:9050';
const agent = new SocksProxyAgent(TOR_SOCKS);

function connect() {
    logger.info(`Connecting to Entry Relay: ${RELAY_WS_URL}`);
    const ws = new WebSocket(RELAY_WS_URL);

    ws.on('open', () => {
        logger.info('Tunnel to Relay established');
        const interval = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'heartbeat', load: 0.1, uptime: process.uptime() }));
            }
        }, 10000);
        ws.on('close', () => clearInterval(interval));
    });

    ws.on('message', async (data) => {
        try {
            const msg = JSON.parse(data.toString());
            if (msg.type === 'dispatch') {
                const { onion_service_id, payload } = msg;
                logger.info({ onion_service_id }, 'Forwarding ciphertext to client');
                
                // We send to the root of the onion service (Port 80)
                // The onion-pipe client (nginx) will forward this to the local target
                await axios.post(`http://${onion_service_id}.onion/`, 
                    { payload }, 
                    { 
                        httpAgent: agent, 
                        httpsAgent: agent, 
                        timeout: 30000,
                        headers: { 'Content-Type': 'application/json' }
                    }
                );
            }
        } catch (err: any) {
            logger.error({ error: err.message }, 'Bridge forwarding failed');
        }
    });

    ws.on('close', () => {
        logger.warn('Relay connection lost. Retrying...');
        setTimeout(connect, 5000);
    });
}

connect();
