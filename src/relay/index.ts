import express, { Request, Response, NextFunction } from 'express';
import WebSocket, { WebSocketServer } from 'ws';
import { RedisService, TokenMetadata } from '../common/redis';
import { CryptoService } from '../common/crypto';
import { getSecret } from '../common/secrets';
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';
import * as http from 'http';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { RedisStore } from 'connect-redis';
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

const redis = new RedisService(process.env.REDIS_URL);

app.use(session({
    store: new RedisStore({
        client: redis.getClient(),
        prefix: "sess:",
    }),
    secret: getSecret('SESSION_SECRET', uuidv4()),
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

const bridgeConnections = new Map<string, WebSocket>();
const PORT = process.env.PORT || 3000;

// --- MASTER MODE CONFIG ---
const IS_MASTER = process.env.MASTER === 'true';
const ADMIN_USER = getSecret('ADMIN_USER', 'admin');
const ADMIN_PASSWORD = getSecret('ADMIN_PASSWORD', 'admin');

passport.serializeUser((user: any, done) => done(null, user));
passport.deserializeUser((user: any, done) => done(null, user));

if (IS_MASTER) {
    const githubClientId = getSecret('GITHUB_CLIENT_ID');
    const githubClientSecret = getSecret('GITHUB_CLIENT_SECRET');

    if (githubClientId && githubClientSecret) {
        logger.info('🔑 GitHub OAuth Strategy initialized');
        passport.use(new GitHubStrategy({
            clientID: githubClientId,
            clientSecret: githubClientSecret,
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
        (req, res) => {
            const isCli = (req.session as any).isCliAuth;
            if (isCli) {
                delete (req.session as any).isCliAuth;
                return res.redirect('/cli-auth');
            }
            res.redirect('/dashboard');
        }
    );

    app.get('/cli-auth', requireAuth, async (req, res) => {
        const isAdmin = req.cookies.auth_admin === 'true';
        if (isAdmin) return res.send("Admin cannot use CLI auth codes.");
        
        const user = req.user as PassportUser;
        const code = await redis.createAuthCode(user.id);
        
        res.send(`
            <html>
            <head>
                <title>CLI Authentication | Onion-Pipe</title>
                <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🧅</text></svg>">
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-slate-950 text-slate-100 font-sans min-h-screen flex items-center justify-center">
                <div class="max-w-md w-full bg-slate-900 p-8 rounded-2xl shadow-2xl border border-slate-800 text-center">
                    <h1 class="text-2xl font-bold mb-2">CLI Authentication</h1>
                    <p class="text-slate-500 text-sm mb-8 font-mono uppercase tracking-widest leading-none">Your One-Time Device Code</p>
                    
                    <div class="bg-slate-950 border-2 border-dashed border-indigo-500/50 p-6 rounded-xl mb-6">
                        <span class="text-5xl font-black font-mono tracking-[0.2em] text-indigo-400">${code}</span>
                    </div>

                    <p class="text-slate-400 text-xs mb-8">Paste this code into your terminal to complete the <code class="bg-black px-1 text-indigo-300">onion-pipe login</code> command. It expires in 5 minutes.</p>

                    <a href="/dashboard" class="text-slate-500 hover:text-white text-xs underline transition">Go to Dashboard</a>
                </div>
            </body>
            </html>
        `);
    });

    app.post('/auth/cli/exchange', async (req, res) => {
        const { code } = req.body;
        if (!code) return res.status(400).json({ error: 'Code required' });
        
        const apiKey = await redis.exchangeAuthCode(code);
        if (!apiKey) return res.status(401).json({ error: 'Invalid or expired code' });
        
        res.json({ api_key: apiKey });
    });

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
        const apiKey = !isAdmin ? await redis.getOrCreateUserApiKey(user.id) : null;
        
        res.send(`
            <html>
            <head>
                <title>Dashboard | Onion-Pipe</title>
                <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🧅</text></svg>">
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
                    ${!isAdmin ? `
                    <div class="bg-indigo-600/10 border border-indigo-500/30 p-4 rounded-xl mb-8 flex items-center justify-between">
                        <div class="flex-1">
                            <p class="text-[10px] uppercase font-bold text-indigo-400 mb-1">Your Account API Key (Secret)</p>
                            <div class="flex items-center space-x-3">
                                <div class="relative flex items-center bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
                                    <code id="api-key-text" data-key="${apiKey}" class="text-indigo-200 font-mono text-sm" style="-webkit-text-security: disc;">${apiKey}</code>
                                    <button onclick="toggleApiKey()" class="ml-2 text-slate-500 hover:text-indigo-400 transition" title="Reveal API Key">
                                        <svg id="eye-icon" xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                        </svg>
                                    </button>
                                </div>
                                <div class="flex space-x-2">
                                    <button onclick="copyApiKey()" class="p-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-400 hover:text-white transition" title="Copy to Clipboard">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 012-2v-8a2 2 0 01-2-2h-8a2 2 0 01-2 2v8a2 2 0 012 2z" />
                                        </svg>
                                    </button>
                                    <button onclick="rotateApiKey()" class="p-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-400 hover:text-white transition" title="Rotate/Refresh Key">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                        </svg>
                                    </button>
                                </div>
                            </div>
                        </div>
                        <div class="text-right">
                            <p class="text-[10px] text-slate-500 uppercase font-bold">CLI Usage</p>
                            <code class="text-[10px] bg-black/50 px-2 py-1 rounded text-slate-400 font-mono">onion-pipe login</code>
                        </div>
                    </div>
                    ` : ''}

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
                            <div class="flex space-x-2">
                                ${!isAdmin ? `<button onclick="showAddHook()" class="text-xs bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5 rounded-md transition font-medium uppercase tracking-wider">+ Add New Hook</button>` : ''}
                                <button onclick="refreshTokens()" class="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-md transition font-medium uppercase tracking-wider">Refresh Hooks</button>
                            </div>
                        </div>

                        <!-- Add Hook Modal/Form -->
                        <div id="add-hook-form" class="hidden p-6 border-b border-slate-800 bg-slate-800/20">
                            <h3 class="text-sm font-bold mb-4 text-indigo-300 uppercase tracking-widest">Register New Mapping</h3>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-[10px] text-slate-500 uppercase font-bold mb-1">Onion Service ID (without .onion)</label>
                                    <input id="new-onion" type="text" placeholder="e.g. v2c3...f4" class="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-indigo-500">
                                </div>
                                <div>
                                    <label class="block text-[10px] text-slate-500 uppercase font-bold mb-1">X25519 Public Key (Hex)</label>
                                    <input id="new-pubkey" type="text" placeholder="Get this from your client" class="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-indigo-500">
                                </div>
                            </div>
                            <div class="mt-4 flex justify-end space-x-3">
                                <button onclick="showAddHook(false)" class="text-xs text-slate-400 hover:text-white transition">Cancel</button>
                                <button onclick="submitNewHook()" class="bg-indigo-600 hover:bg-indigo-500 px-4 py-2 rounded text-xs font-bold transition">Create Hook</button>
                            </div>
                        </div>

                        <div class="p-6">
                            <div id="tokens-list" class="space-y-4">
                                <p class="text-slate-500 italic text-center py-10">Fetching your registered services...</p>
                            </div>
                        </div>
                    </div>
                </main>

                <script>
                    function showAddHook(show = true) {
                        document.getElementById('add-hook-form').classList.toggle('hidden', !show);
                    }

                    async function submitNewHook() {
                        const onion = document.getElementById('new-onion').value.trim();
                        const pubkey = document.getElementById('new-pubkey').value.trim();
                        if (!onion || !pubkey) return alert('Please fill all fields');

                        try {
                            const res = await fetch('/register', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ 
                                    onion_service_id: onion.replace('.onion', ''),
                                    public_key: pubkey
                                })
                            });
                            if (!res.ok) throw new Error('Failed to register');
                            const data = await res.json();
                            alert('Hook created successfully! Token: ' + data.token);
                            showAddHook(false);
                            document.getElementById('new-onion').value = '';
                            document.getElementById('new-pubkey').value = '';
                            refreshTokens();
                        } catch (e) { alert(e.message); }
                    }

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
                                            <span class="px-2 py-0.5 bg-green-500/20 text-green-400 text-[10px] font-bold uppercase rounded leading-none">\${t.metadata.status}</span>
                                            <code class="text-indigo-400 font-mono text-xs truncate font-bold">\${t.token}</code>
                                        </div>
                                        <p class="text-slate-300 font-mono text-sm truncate">\${t.metadata.onion_service_id}.onion</p>
                                        <p class="text-[10px] text-slate-600 font-mono italic">Created: \${new Date(t.metadata.created_at * 1000).toLocaleString()}</p>
                                    </div>
                                    <div class="flex gap-2">
                                        <button onclick="deleteToken('\${t.token}')" class="bg-red-500/10 hover:bg-red-500/20 text-red-500 px-3 py-1.5 rounded text-xs font-bold transition">DELETE</button>
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

                    function toggleApiKey() {
                        const el = document.getElementById('api-key-text');
                        const icon = document.getElementById('eye-icon');
                        if (el.style.webkitTextSecurity === 'disc') {
                            el.style.webkitTextSecurity = 'none';
                            icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.542-7a10.017 10.017 0 012.49-4.835m11.24 11.24A9.965 9.965 0 0015 12a3 3 0 11-6 0c0 .408.082.797.23 1.154m6.77 6.77l-6.77-6.77m9.508 9.508l-9.508-9.508" />';
                        } else {
                            el.style.webkitTextSecurity = 'disc';
                            icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />';
                        }
                    }

                    function copyApiKey() {
                        const el = document.getElementById('api-key-text');
                        const text = el.getAttribute('data-key');
                        navigator.clipboard.writeText(text);
                        alert('API Key copied to clipboard!');
                    }

                    async function rotateApiKey() {
                        if (!confirm('Are you sure? This will invalidate your current API key and you will need to re-login on your local CLI.')) return;
                        const res = await fetch('/dashboard/api-key/rotate', { method: 'POST' });
                        if (res.ok) window.location.reload();
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

    app.post('/dashboard/api-key/rotate', requireAuth, async (req, res) => {
        const isAdmin = req.cookies.auth_admin === 'true';
        if (isAdmin) return res.status(400).json({ error: 'Admin has no API key' });
        
        const user = req.user as PassportUser;
        const newKey = await redis.rotateUserApiKey(user.id);
        res.json({ api_key: newKey });
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
    const { onion_service_id, public_key, registration_secret, github_id, token: apiKey } = req.body;

    let targetUserId = null;

    // 1. If an API Key (token) is provided, validate it
    if (apiKey) {
        const ownerId = await redis.getUserIdByApiKey(apiKey);
        if (!ownerId) {
            return res.status(401).json({ error: 'Invalid User API Token' });
        }
        targetUserId = ownerId;
    }

    // 2. If no API Key, fallback to Registration Secret (Legacy/Anonymous mode)
    if (!targetUserId && IS_MASTER && process.env.REGISTRATION_SECRET) {
        if (registration_secret !== process.env.REGISTRATION_SECRET) {
            return res.status(403).json({ error: 'Unauthorized registration: Please provide a valid API Token' });
        }
    }

    const token = uuidv4();
    const metadata: TokenMetadata = {
        onion_service_id,
        public_key,
        status: 'active',
        created_at: Math.floor(Date.now() / 1000).toString()
    };

    // 3. Associate with the User (from API Key, Session, or explicit ID)
    if (targetUserId) {
        metadata.github_id = targetUserId;
    } else if (req.user) {
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
