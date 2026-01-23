import { createClient } from 'redis';
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';
import { getSecret } from './secrets';

const logger = pino({ name: 'RedisClient' });

export interface TokenMetadata {
    onion_service_id: string;
    public_key: string;
    status: 'active' | 'disabled';
    created_at: string;
    github_id?: string;
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
        let finalUrl = url;
        const password = getSecret('REDIS_PASSWORD');
        
        if (password) {
            try {
                const parsedUrl = new URL(url);
                // Only inject password if it's not already there
                if (!parsedUrl.password) {
                    parsedUrl.password = password;
                    finalUrl = parsedUrl.toString();
                }
            } catch (e) {
                // If url is just a host, construct a proper redis url
                if (!url.startsWith('redis://')) {
                    finalUrl = `redis://:${password}@${url}`;
                }
            }
        }

        this.client = createClient({ url: finalUrl });
        this.client.on('error', (err) => logger.error('Redis Error', err));
    }

    getClient() {
        return this.client;
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
        if (metadata.github_id) {
            await this.client.sAdd(`user_tokens:${metadata.github_id}`, token);
        }
        await this.client.sAdd('all_tokens', token);
    }

    async getUserTokens(githubId: string): Promise<{token: string, metadata: TokenMetadata}[]> {
        const tokens = await this.client.sMembers(`user_tokens:${githubId}`);
        const result = [];
        for (const token of tokens) {
            const meta = await this.getTokenMetadata(token);
            if (meta) result.push({ token, metadata: meta });
        }
        return result;
    }

    async getOrCreateUserApiKey(githubId: string): Promise<string> {
        let key = await this.client.get(`api_key:${githubId}`);
        if (!key) {
            key = `op_${uuidv4().replace(/-/g, '')}`;
            await this.client.set(`api_key:${githubId}`, key);
            await this.client.set(`api_key_owner:${key}`, githubId);
        }
        return key;
    }

    async rotateUserApiKey(githubId: string): Promise<string> {
        const oldKey = await this.client.get(`api_key:${githubId}`);
        if (oldKey) {
            await this.client.del(`api_key_owner:${oldKey}`);
        }
        const newKey = `op_${uuidv4().replace(/-/g, '')}`;
        await this.client.set(`api_key:${githubId}`, newKey);
        await this.client.set(`api_key_owner:${newKey}`, githubId);
        return newKey;
    }

    async getUserIdByApiKey(apiKey: string): Promise<string | null> {
        return await this.client.get(`api_key_owner:${apiKey}`);
    }

    async createAuthCode(githubId: string): Promise<string> {
        const code = Math.random().toString(36).substring(2, 8).toUpperCase(); // 6 chars
        await this.client.set(`auth_code:${code}`, githubId, { EX: 300 }); // 5 mins expiry
        return code;
    }

    async exchangeAuthCode(code: string): Promise<string | null> {
        const githubId = await this.client.get(`auth_code:${code}`);
        if (!githubId) return null;
        await this.client.del(`auth_code:${code}`);
        return await this.getOrCreateUserApiKey(githubId);
    }

    async getAllTokens(): Promise<{token: string, metadata: TokenMetadata}[]> {
        const tokens = await this.client.sMembers('all_tokens');
        const result = [];
        for (const token of tokens) {
            const meta = await this.getTokenMetadata(token);
            if (meta) result.push({ token, metadata: meta });
        }
        return result;
    }

    async deleteToken(token: string, githubId?: string) {
        await this.client.del(`token:${token}`);
        await this.client.sRem('all_tokens', token);
        if (githubId) {
            await this.client.sRem(`user_tokens:${githubId}`, token);
        }
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
