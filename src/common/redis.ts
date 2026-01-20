import { createClient } from 'redis';
import pino from 'pino';

const logger = pino({ name: 'RedisClient' });

export interface TokenMetadata {
    onion_service_id: string;
    public_key: string;
    status: 'active' | 'disabled';
    created_at: string;
}

export interface BridgeHeartbeat {
    bridge_id: string;
    load: number;
    uptime: number;
    last_seen: number;
}

export class RedisService {
    private client;

    constructor(url: string = process.env.REDIS_URL || 'redis://localhost:6379') {
        this.client = createClient({ url });
        this.client.on('error', (err) => logger.error('Redis Error', err));
    }

    async connect() {
        if (!this.client.isOpen) {
            await this.client.connect();
        }
    }

    async getTokenMetadata(token: string): Promise<TokenMetadata | null> {
        const data = await this.client.hGetAll(`token:${token}`);
        if (!data || Object.keys(data).length === 0) return null;
        return data as unknown as TokenMetadata;
    }

    async setTokenMetadata(token: string, metadata: TokenMetadata) {
        await this.client.hSet(`token:${token}`, metadata as any);
    }

    async updateBridgeHeartbeat(heartbeat: BridgeHeartbeat) {
        const key = `bridge:${heartbeat.bridge_id}`;
        await this.client.hSet(key, {
            ...heartbeat,
            last_seen: Date.now()
        } as any);
        // Set expiry for bridge health (e.g., 60 seconds)
        await this.client.expire(key, 60);
        // Add to bridge set for discovery
        await this.client.sAdd('active_bridges', heartbeat.bridge_id);
    }

    async getHealthyBridges(): Promise<BridgeHeartbeat[]> {
        const bridgeIds = await this.client.sMembers('active_bridges');
        const bridges: BridgeHeartbeat[] = [];
        
        for (const id of bridgeIds) {
            const data = await this.client.hGetAll(`bridge:${id}`);
            if (data && Object.keys(data).length > 0) {
                bridges.push(data as unknown as BridgeHeartbeat);
            } else {
                await this.client.sRem('active_bridges', id);
            }
        }
        return bridges;
    }
}
