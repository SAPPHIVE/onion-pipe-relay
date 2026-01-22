import express, { Request, Response, NextFunction } from 'express';
import WebSocket, { WebSocketServer } from 'ws';
import { RedisService, TokenMetadata } from '../common/redis';
import { CryptoService } from '../common/crypto';
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';
import * as http from 'http';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GitHubStrategy } from 'passport-github2';

const logger = pino({ name: 'EntryRelay', transport: { target: 'pino-pretty' }, level: process.env.LOG_LEVEL || 'info' });
const app = express();

// Required for secure cookies behind Nginx Proxy Manager
app.set('trust proxy', 1);

interface PassportUser {
    id: string;
    username: string;
    isAdmin: boolean;
}

declare global {
    namespace Express {
        interface User extends PassportUser {}
    }
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET || uuidv4(),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
    }
}));
app.use(passport.initialize());
app.use(passport.session());

const redis = new RedisService(process.env.REDIS_URL);
const bridgeConnections = new Map<string, WebSocket>();
const PORT = process.env.PORT || 3000;

// --- MASTER MODE CONFIG ---
const IS_MASTER = process.env.MASTER === 'true';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

passport.serializeUser((user: any, done) => done(null, user));
passport.deserializeUser((user: any, done) => done(null, user));

if (IS_MASTER) {
    if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
        logger.info('🔑 GitHub OAuth Strategy initialized');
        passport.use(new GitHubStrategy({
            clientID: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
            callbackURL: `${process.env.PUBLIC_RELAY_URL}/auth/github/callback`
        }, (accessToken: string, refreshToken: string, profile: any, done: any) => {
            return done(null, {
                id: profile.id,
                username: profile.username,
                isAdmin: false
            });
        }));
    } else {
        logger.warn('⚠️ GitHub OAuth NOT initialized: Missing CLIENT_ID or CLIENT_SECRET');
    }
}

const requireAuth = (req: Request, res: Response, next: NextFunction) => {
    if (req.isAuthenticated() || req.cookies.auth_admin === 'true') {
        return next();
    }
    res.redirect('/login');
};

const bodyLogger = (req: Request, res: Response, next: NextFunction) => {
    if (IS_MASTER) logger.debug({ path: req.path }, 'Request received');
    next();
};

app.use(bodyLogger);

// --- DASHBOARD ROUTES (MASTER ONLY) ---
if (IS_MASTER) {
    logger.info('👑 Master Mode Enabled: Dashboard active at /dashboard');

    app.get('/', (req, res) => {
        const loggedIn = req.isAuthenticated() || req.cookies.auth_admin === 'true';
        res.send(`
            <html>
            <head>
                <title>Sapphive Onion-Pipe</title>
                <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🧅</text></svg>">
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-slate-900 text-slate-100 font-sans min-h-screen flex items-center justify-center">
                <div class="max-w-md w-full bg-slate-800 p-8 rounded-xl shadow-2xl border border-slate-700 text-center">
                    <div class="flex justify-center mb-6">
                        <div class="bg-indigo-500/20 p-4 rounded-full">
                            <span class="text-4xl text-indigo-400">🧅</span>
                        </div>
                    </div>
                    <h1 class="text-3xl font-bold mb-2">Onion-Pipe</h1>
                    <p class="text-slate-400 mb-8 text-sm uppercase tracking-widest">Public Relay Network</p>
                    
                    <div class="space-y-4">
                        <div class="p-3 bg-slate-900/50 rounded-lg border border-slate-700">
                            <p class="text-xs text-slate-500 mb-1">Network Status</p>
                            <p class="text-green-400 font-mono text-lg">● ONLINE & ACTIVE</p>
                        </div>
                        
                        <div class="pt-4">
                            <a href="${loggedIn ? '/dashboard' : '/login'}" 
                               class="block w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-3 rounded-lg transition duration-200">
                               ${loggedIn ? 'Go to Dashboard' : 'Member Access'}
                            </a>
                        </div>
                    </div>

                    <p class="mt-8 text-xs text-slate-500">
                        Join the network: <br/>
                        <code class="bg-black/50 px-2 py-1 rounded text-indigo-300">onion-pipe register &lt;onion-address&gt;</code>
                    </p>
                </div>
            </body>
            </html>
        `);
    });

    app.get('/login', (req, res) => {
        if (req.isAuthenticated() || req.cookies.auth_admin === 'true') return res.redirect('/dashboard');
        res.send(`
            <html>
            <head>
                <title>Login | Onion-Pipe</title>
                <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🧅</text></svg>">
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-slate-950 text-slate-100 font-sans min-h-screen flex items-center justify-center">
                <div class="max-w-sm w-full bg-slate-900 p-8 rounded-2xl shadow-2xl border border-slate-800">
                    <h1 class="text-2xl font-bold mb-6 text-center">Secure Access</h1>
                    
                    <div class="space-y-4">
                        <a href="/auth/github" 
                           class="flex items-center justify-center space-x-3 w-full bg-white hover:bg-slate-100 text-slate-900 py-3 rounded-lg font-bold transition duration-200">
                            <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.041-1.416-4.041-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                            <span>Sign in with GitHub</span>
                        </a>

                        <div class="relative py-4">
                            <div class="absolute inset-0 flex items-center"><div class="w-full border-t border-slate-800"></div></div>
                            <div class="relative flex justify-center text-xs uppercase"><span class="bg-slate-900 px-2 text-slate-500">Or Admin Login</span></div>
                        </div>

                        <form action="/login" method="POST" class="space-y-4">
                            <div>
                                <input type="text" name="username" placeholder="Admin Username" required
                                    class="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 focus:ring-2 focus:ring-indigo-500 outline-none transition mb-2">
                                <input type="password" name="password" placeholder="System Password" required
                                    class="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 focus:ring-2 focus:ring-indigo-500 outline-none transition">
                            </div>
                            <button type="submit" 
                                class="w-full bg-slate-800 hover:bg-slate-700 py-3 rounded-lg font-bold border border-slate-700 transition duration-200">
                                Admin Entry
                            </button>
                            ${req.query.error ? '<p class="text-red-400 text-sm text-center">Invalid credentials</p>' : ''}
                        </form>
                    </div>
                </div>
            </body>
            </html>
        `);
    });

    app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

    app.get('/auth/github/callback', 
        passport.authenticate('github', { failureRedirect: '/login' }),
        (req, res) => res.redirect('/dashboard')
    );

    app.post('/login', (req, res) => {
        if (req.body.username === ADMIN_USER && req.body.password === ADMIN_PASSWORD) {
            res.cookie('auth_admin', 'true', { httpOnly: true, secure: true, sameSite: 'strict' });
            return res.redirect('/dashboard');
        }
        res.redirect('/login?error=1');
    });

    app.get('/logout', (req, res) => {
        req.logout(() => {
            res.clearCookie('auth_admin');
            res.redirect('/');
        });
    });
    
    app.get('/dashboard', requireAuth, async (req, res) => {
        const isAdmin = req.cookies.auth_admin === 'true';
        const user = req.user as PassportUser;
        const username = isAdmin ? 'Super Admin' : user.username;
        
        res.send(`
            <html>
            <head>
                <title>Dashboard | Onion-Pipe</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-slate-950 text-slate-100 font-sans">
                <nav class="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
                    <div class="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center">
                        <div class="flex items-center space-x-2">
                            <span class="text-2xl">🧅</span>
                            <span class="font-bold tracking-tight">Onion-Pipe Dashboard</span>
                        </div>
                        <div class="flex items-center space-x-4">
                            <span class="text-slate-400 text-sm italic">Logged in as ${username}</span>
                            <a href="/logout" class="bg-slate-800 hover:bg-slate-700 px-4 py-1.5 rounded-lg text-sm font-medium transition">Sign Out</a>
                        </div>
                    </div>
                </nav>

                <main class="max-w-7xl mx-auto px-4 py-8">
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg">
                            <p class="text-slate-500 text-sm mb-1">Network Status</p>
                            <p class="text-2xl font-bold text-green-400">● Active</p>
                        </div>
                        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg">
                            <p class="text-slate-500 text-sm mb-1">Connected Bridges</p>
                            <p class="text-2xl font-bold">${bridgeConnections.size}</p>
                        </div>
                        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg">
                            <p class="text-slate-500 text-sm mb-1">Public Endpoint</p>
                            <p class="text-lg font-mono truncate text-indigo-400">${process.env.PUBLIC_RELAY_URL?.replace('https://', '') || 'local'}</p>
                        </div>
                    </div>

                    ${isAdmin ? `
                    <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg mb-8">
                        <div class="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-indigo-500/5">
                            <h2 class="font-bold text-lg">Infrastructure Telemetry (Admin Only)</h2>
                            <button onclick="refreshNodes()" class="text-xs bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5 rounded-md transition font-medium uppercase tracking-wider">Refresh Bridges</button>
                        </div>
                        <div class="p-6">
                            <pre id="nodes" class="bg-slate-950 p-4 rounded-xl border border-slate-800 overflow-x-auto text-indigo-400 text-sm font-mono min-h-[100px]">Loading bridge telemetry...</pre>
                        </div>
                    </div>
                    ` : ''}

                    <div class="bg-slate-900 border border-slate-800 rounded-2xl shadow-lg">
                        <div class="px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                            <h2 class="font-bold text-lg">${isAdmin ? 'All Registered Hooks' : 'Your Managed Hooks'}</h2>
                            <button onclick="refreshTokens()" class="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-md transition">Refresh Hooks</button>
                        </div>
                        <div class="p-6">
                            <div id="tokens-list" class="space-y-4">
                                <p class="text-slate-500 italic text-center py-10">Fetching your registered services...</p>
                            </div>
                        </div>
                    </div>
                </main>

                <script>
                    async function refreshNodes() {
                        const pre = document.getElementById('nodes');
                        if (!pre) return;
                        try {
                            const res = await fetch('/dashboard/nodes');
                            const data = await res.json();
                            pre.innerText = data.length ? JSON.stringify(data, null, 2) : "No external bridges.";
                        } catch (e) { pre.innerText = "Error."; }
                    }

                    async function refreshTokens() {
                        const list = document.getElementById('tokens-list');
                        try {
                            const res = await fetch('/dashboard/tokens');
                            const data = await res.json();
                            if (data.length === 0) {
                                list.innerHTML = '<div class="text-center py-10 border-2 border-dashed border-slate-800 rounded-xl text-slate-500">No hooks registered. Use the CLI to register a service.</div>';
                                return;
                            }
                            list.innerHTML = data.map(t => \`
                                <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
                                    <div class="flex-1 min-w-0">
                                        <div class="flex items-center space-x-2 mb-1">
                                            <span class="px-2 py-0.5 bg-green-500/20 text-green-400 text-[10px] font-bold uppercase rounded leading-none">\\\${t.metadata.status}</span>
                                            <code class="text-indigo-400 font-mono text-xs truncate font-bold">\\\${t.token}</code>
                                        </div>
                                        <p class="text-slate-300 font-mono text-sm truncate">\\\${t.metadata.onion_service_id}.onion</p>
                                        <p class="text-[10px] text-slate-600 font-mono italic">Created: \\\${new Date(t.metadata.created_at * 1000).toLocaleString()}</p>
                                    </div>
                                    <div class="flex gap-2">
                                        <button onclick="deleteToken('\\\${t.token}')" class="bg-red-500/10 hover:bg-red-500/20 text-red-500 px-3 py-1.5 rounded text-xs font-bold transition">DELETE</button>
                                    </div>
                                </div>
                            \`).join('');
                        } catch (e) { list.innerHTML = 'Failed to load.'; }
                    }

                    async function deleteToken(token) {
                        if (!confirm('Are you sure you want to delete this mapping?')) return;
                        await fetch('/dashboard/tokens/' + token, { method: 'DELETE' });
                        refreshTokens();
                    }

                    refreshNodes();
                    refreshTokens();
                </script>
            </body>
            </html>
        `);
    });

    app.get('/dashboard/nodes', requireAuth, async (req, res) => {
        if (req.cookies.auth_admin !== 'true') return res.status(401).json({ error: 'Admin only' });
        const bridges = await redis.getHealthyBridges();
        res.json(bridges);
    });

    app.get('/dashboard/tokens', requireAuth, async (req, res) => {
        const isAdmin = req.cookies.auth_admin === 'true';
        const user = req.user as PassportUser;
        
        if (isAdmin) {
            const tokens = await redis.getAllTokens();
            return res.json(tokens);
        } else {
            const tokens = await redis.getUserTokens(user.id);
            return res.json(tokens);
        }
    });

    app.delete('/dashboard/tokens/:token', requireAuth, async (req, res) => {
        const isAdmin = req.cookies.auth_admin === 'true';
        const token = req.params.token as string;
        
        if (isAdmin) {
            await redis.deleteToken(token);
            res.status(204).end();
        } else {
            const user = req.user as PassportUser;
            const meta = await redis.getTokenMetadata(token);
            if (meta?.github_id === user.id) {
                await redis.deleteToken(token, user.id);
                res.status(204).end();
            } else {
                res.status(403).end();
            }
        }
    });
}

app.get('/health', (req, res) => res.status(200).send('OK'));

// --- GLOBAL ERROR HANDLER ---
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    logger.error({ err: err.message, stack: err.stack }, 'Unhandled Server Error');
    res.status(500).send('Internal Server Error: check relay logs');
});

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
    const { onion_service_id, public_key, registration_secret, github_id } = req.body;

    // Optional restriction if Master specifies it
    if (IS_MASTER && process.env.REGISTRATION_SECRET) {
        if (registration_secret !== process.env.REGISTRATION_SECRET) {
            return res.status(403).json({ error: 'Unauthorized registration' });
        }
    }

    const token = uuidv4();
    const metadata: TokenMetadata = {
        onion_service_id,
        public_key,
        status: 'active',
        created_at: Math.floor(Date.now() / 1000).toString()
    };

    // Associate with GitHub user if authenticated or provided
    if (req.user) {
        metadata.github_id = (req.user as any).id;
    } else if (github_id) {
        metadata.github_id = github_id;
    }

    await redis.setTokenMetadata(token, metadata);

    logger.info({ token, onion_service_id, userId: metadata.github_id }, 'New client registered');
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

const server = app.listen(Number(PORT), '0.0.0.0', async () => {
    await redis.connect();
    logger.info(`Relay running on 0.0.0.0:${PORT}`);
});

server.on('upgrade', (request: http.IncomingMessage, socket: any, head: Buffer) => {
    wss.handleUpgrade(request, socket, head, (ws) => wss.emit('connection', ws, request));
});
