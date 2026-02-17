import WebSocket from 'ws';
import { SocksProxyAgent } from 'socks-proxy-agent';
import axios from 'axios';
import pino from 'pino';

const logger = pino({ name: 'LOOHIVE-Bridge', transport: { target: 'pino-pretty' } });
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
                const { onion_service_id, payload, requestId } = msg;
                logger.info({ onion_service_id, requestId }, 'Forwarding request to client tunnel');
                
                try {
                    // Forward the encrypted request payload to the .onion service
                    const response = await axios.post(`http://${onion_service_id}.onion/`, 
                        { payload }, 
                        { 
                            httpAgent: agent, 
                            httpsAgent: agent, 
                            timeout: 40000, // 40s timeout for hidden service processing
                            headers: { 'Content-Type': 'application/json' },
                            responseType: 'arraybuffer', // Handle binary payloads correctly
                            decompress: false, // DON'T decompress; let the browser handle it
                            validateStatus: () => true // Allow any status code
                        }
                    );

                    // Send the application response back to the Relay
                    // Use base64 for the data buffer to ensure safe transport over JSON
                    ws.send(JSON.stringify({
                        type: 'response',
                        requestId,
                        status: response.status,
                        headers: response.headers,
                        data: Buffer.from(response.data).toString('base64'),
                        isBinary: true
                    }));
                } catch (err: any) {
                    const status = err.response?.status || 502;
                    logger.error({ error: err.message, requestId, status }, 'Tunnel request failed');
                    
                    // Notify Relay that the tunnel failed
                    ws.send(JSON.stringify({
                        type: 'response',
                        requestId,
                        status,
                        data: { 
                            error: 'TUNNEL_REACH_ERROR', 
                            message: 'Could not communicate with the local onion-pipe client.',
                            details: err.message 
                        }
                    }));
                }
            }
        } catch (err: any) {
            logger.error({ error: err.message }, 'Bridge message processing failed');
        }
    });

    ws.on('close', () => {
        logger.warn('Relay connection lost. Retrying...');
        setTimeout(connect, 5000);
    });
}

connect();
