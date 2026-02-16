import { createClient } from 'redis';
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';
import { getSecret } from './secrets';

const logger = pino({ name: 'LOOHIVE-Redis' });

export interface TokenMetadata {
    onion_service_id: string;
    public_key: string;
    status: 'active' | 'disabled';
    created_at: string;
    github_id?: string;
    project_name?: string;
}

export interface BridgeHeartbeat {
    bridge_id: string;
    load: number;
    uptime: number;
    last_seen: number;
}

export interface WebAuthnCredential {
    credentialID: string;
    publicKey: string; 
    counter: number;
    transports?: any[];
}

export interface UserMfa {
    totp_enabled: boolean;
    totp_secret?: string;
    backup_codes?: string[]; // stored as hashes
    webauthn_credentials: WebAuthnCredential[];
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
            // Track the user in the global user list
            await this.client.sAdd('all_users', metadata.github_id);
        }
        await this.client.sAdd('all_tokens', token);
    }

    async getAllUsers(): Promise<{github_id: string, username: string, hook_count: number, is_banned: boolean}[]> {
        const userIds = await this.client.sMembers('all_users');
        const result = [];
        for (const id of userIds) {
            const username = await this.client.get(`username:${id}`) || 'Unknown';
            
            // Accurate Hook Count & Cleanup
            const tokens = await this.client.sMembers(`user_tokens:${id}`);
            let validCount = 0;
            for (const t of tokens) {
                if (await this.client.exists(`token:${t}`)) {
                    validCount++;
                } else {
                    await this.client.sRem(`user_tokens:${id}`, t);
                }
            }

            const isBanned = Boolean(await this.client.sIsMember('banned_users', id));
            result.push({ github_id: id, username, hook_count: validCount, is_banned: isBanned });
        }
        return result;
    }

    async getPaginatedUsers(page: number, limit: number, search: string = '', status: string = 'all'): Promise<{ users: any[], total: number }> {
        // Optimization: For "millions", this should rely on a search index (RediSearch)
        // For now, we fetch IDs and filter in memory (acceptable for < 100k)
        const allIds = await this.client.sMembers('all_users');
        let filteredUsers = [];
        
        for (const id of allIds) {
            const username = await this.client.get(`username:${id}`) || 'Unknown';
            const isBanned = Boolean(await this.client.sIsMember('banned_users', id));

            // Status Filter Logic
            if (status === 'banned' && !isBanned) continue;
            if (status === 'active' && isBanned) continue;

            // Search Logic (Username or ID)
            if (search && !username.toLowerCase().includes(search.toLowerCase()) && !id.includes(search)) {
                continue;
            }
            
            // Accurate Hook Count (Verifies existence and cleans up ghosts)
            const tokens = await this.client.sMembers(`user_tokens:${id}`);
            let validTokens = [];
            for (const t of tokens) {
                const exists = await this.client.exists(`token:${t}`);
                if (exists) {
                    validTokens.push(t);
                } else {
                    // Self-healing: Remove ghost token from user set
                    await this.client.sRem(`user_tokens:${id}`, t);
                }
            }
            
            const hookCount = validTokens.length;
            filteredUsers.push({ github_id: id, username, hook_count: hookCount, is_banned: isBanned });
        }

        // Sort by username
        filteredUsers.sort((a, b) => a.username.localeCompare(b.username));

        const total = filteredUsers.length;
        const start = (page - 1) * limit;
        const paginated = filteredUsers.slice(start, start + limit);

        return { users: paginated, total };
    }

    async setUserBanStatus(githubId: string, ban: boolean) {
        if (ban) {
            await this.client.sAdd('banned_users', githubId);
            // Optional: Immediately revoke their session or tokens?
            // For now, middleware in index.ts should check this set
        } else {
            await this.client.sRem('banned_users', githubId);
        }
    }

    async isUserBanned(githubId: string): Promise<boolean> {
        return Boolean(await this.client.sIsMember('banned_users', githubId));
    }

    async getUserStats(): Promise<{ total: number, active: number, banned: number }> {
        const total = await this.client.sCard('all_users');
        const banned = await this.client.sCard('banned_users');
        return {
            total,
            banned,
            active: Math.max(0, total - banned)
        };
    }
    
    async getPaginatedTokens(userId: string | null, page: number, limit: number, search: string = ''): Promise<{ tokens: any[], total: number }> {
        // userId null means ALL tokens (Admin view)
        let tokenIds: string[] = [];
        if (userId) {
            tokenIds = await this.client.sMembers(`user_tokens:${userId}`);
        } else {
            tokenIds = await this.client.sMembers('all_tokens');
        }

        let filteredTokens: any[] = [];
        for (const tid of tokenIds) {
            const meta = await this.getTokenMetadata(tid);
            if (!meta) {
                // Self-healing: Remove ghost from appropriate sets
                if (userId) await this.client.sRem(`user_tokens:${userId}`, tid);
                await this.client.sRem('all_tokens', tid);
                continue;
            }

            // Add owner username for Admin View
            let ownerName = 'Anonymous';
            if (meta.github_id) {
                ownerName = await this.client.get(`username:${meta.github_id}`) || meta.github_id;
            }

            if (search) {
                const searchLower = search.toLowerCase();
                const projectName = (meta.project_name || 'Default').toLowerCase();
                const matches = tid.includes(search) || 
                                meta.onion_service_id.includes(searchLower) || 
                                ownerName.toLowerCase().includes(searchLower) ||
                                projectName.includes(searchLower) ||
                                (meta.github_id && meta.github_id.toString().includes(search));
                if (!matches) continue;
            }

            filteredTokens.push({
                metadata: meta,
                token: tid,
                owner_name: ownerName
            });
        }

        // Sort by creation date (newest first)
        filteredTokens.sort((a, b) => parseInt(b.metadata.created_at) - parseInt(a.metadata.created_at));

        const total = filteredTokens.length;
        const start = (page - 1) * limit;
        const result = filteredTokens.slice(start, start + limit);
        
        return { tokens: result, total };
    }

    async updateTokenProject(token: string, githubId: string, projectName: string) {
        const meta = await this.getTokenMetadata(token);
        if (!meta || meta.github_id !== githubId) {
            throw new Error('Unauthorized or token not found');
        }
        meta.project_name = projectName;
        await this.client.hSet(`token:${token}`, meta as any);
    }

    async saveUsername(githubId: string, username: string) {
        await this.client.set(`username:${githubId}`, username);
        await this.client.sAdd('all_users', githubId);
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
        const meta = await this.getTokenMetadata(token);
        const ownerId = githubId || meta?.github_id;
        
        await this.client.del(`token:${token}`);
        await this.client.sRem('all_tokens', token);
        
        if (ownerId) {
            await this.client.sRem(`user_tokens:${ownerId}`, token);
        }
    }

    async deleteUser(githubId: string) {
        // 1. Delete all tokens associated with the user
        const tokens = await this.client.sMembers(`user_tokens:${githubId}`);
        for (const token of tokens) {
            await this.deleteToken(token, githubId);
        }
        
        // 2. Delete user's API keys
        const apiKey = await this.client.get(`api_key:${githubId}`);
        if (apiKey) {
            await this.client.del(`api_key_owner:${apiKey}`);
            await this.client.del(`api_key:${githubId}`);
        }
        
        // 3. Delete MFA data and username
        await this.client.del(`user_mfa:${githubId}`);
        await this.client.del(`username:${githubId}`);
        
        // 4. Remove from global user list
        await this.client.sRem('all_users', githubId);
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

    // --- MFA PERSISTENCE ---

    async getUserMfa(githubId: string): Promise<UserMfa> {
        const data = await this.client.get(`user_mfa:${githubId}`);
        if (!data) {
            return {
                totp_enabled: false,
                webauthn_credentials: []
            };
        }
        return JSON.parse(data);
    }

    async updateUserMfa(githubId: string, mfa: UserMfa) {
        await this.client.set(`user_mfa:${githubId}`, JSON.stringify(mfa));
    }

    /**
     * Stores a temporary WebAuthn challenge for verification
     */
    async setWebAuthnChallenge(githubId: string, challenge: string) {
        await this.client.set(`webauthn_challenge:${githubId}`, challenge, { EX: 300 }); // 5 min
    }

    async getWebAuthnChallenge(githubId: string): Promise<string | null> {
        return await this.client.get(`webauthn_challenge:${githubId}`);
    }
}
