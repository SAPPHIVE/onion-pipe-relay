import express, { Request, Response, NextFunction } from "express";
import WebSocket, { WebSocketServer } from "ws";
import { RedisService, TokenMetadata } from "../common/redis";
import { CryptoService } from "../common/crypto";
import { getSecret } from "../common/secrets";
import pino from "pino";
import { v4 as uuidv4 } from "uuid";
import * as http from "http";
import path from "path";
import cookieParser from "cookie-parser";
import session from "express-session";
import { RedisStore } from "connect-redis";
import passport from "passport";
import { Strategy as GitHubStrategy } from "passport-github2";
import { Strategy as LocalStrategy } from "passport-local";
import crypto from "crypto";
import { setupMfaRoutes } from "./mfa";

const logger = pino({
  name: "EntryRelay",
  transport: { target: "pino-pretty" },
  level: process.env.LOG_LEVEL || "info",
});
const app = express();

// Required for secure cookies behind Nginx Proxy Manager
app.set("trust proxy", 1);

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

// Serve assets
const assetPath = path.join(__dirname, "..", "assets");
app.use("/assets", express.static(assetPath));
app.get("/logo.png", (req, res) => {
  res.sendFile(path.join(assetPath, "logo", "logo.png"));
});

const redis = new RedisService(process.env.REDIS_URL);

// --- SESSION HARDENING ---
const getFingerprint = (req: Request) => {
  const ua = req.get("User-Agent") || "unknown";
  const ip = ((req.headers["x-forwarded-for"] as string) || req.ip || "unknown")
    .split(",")[0]
    .trim();
  return crypto.createHash("sha256").update(`${ua}|${ip}`).digest("hex");
};

app.use(
  session({
    store: new RedisStore({
      client: redis.getClient(),
      prefix: "sess:",
    }),
    name: process.env.NODE_ENV === "production" ? "__Host-op-sid" : "op-sid",
    secret: getSecret("SESSION_SECRET", uuidv4()),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24, // 1 day (shorter for production)
    },
  }),
);

// Session Hijacking Protection (Fingerprinting)
app.use((req, res, next) => {
  if (req.session) {
    const currentFingerprint = getFingerprint(req);
    if (!(req.session as any).fingerprint) {
      (req.session as any).fingerprint = currentFingerprint;
    } else if ((req.session as any).fingerprint !== currentFingerprint) {
      const oldFp = (req.session as any).fingerprint;
      logger.warn(
        {
          user_id: req.user?.id,
          old_fp: oldFp,
          new_fp: currentFingerprint,
          ip: (req.headers["x-forwarded-for"] as string) || req.ip || "unknown",
          ua: req.get("User-Agent"),
        },
        "⚠️ Session Hijack attempt detected - Fingerprint mismatch",
      );

      return req.session.destroy(() => {
        res.clearCookie("op-sid");
        if (
          req.xhr ||
          req.path.startsWith("/api/") ||
          (req.headers.accept || "").includes("json")
        ) {
          res
            .status(401)
            .json({ error: "Session invalidated. Please login again." });
        } else {
          res.redirect("/login?error=hijack");
        }
      });
    }
  }
  next();
});

app.use(passport.initialize());
app.use(passport.session());

const bridgeConnections = new Map<string, WebSocket>();
const PORT = process.env.PORT || 3000;

// --- MASTER MODE CONFIG ---
const IS_MASTER = process.env.MASTER === "true";
const ADMIN_USER = getSecret("ADMIN_USER", "admin");
const ADMIN_PASSWORD = getSecret("ADMIN_PASSWORD", "admin");

passport.serializeUser((user: any, done) => done(null, user));
passport.deserializeUser((user: any, done) => done(null, user));

if (IS_MASTER) {
  const githubClientId = getSecret("GITHUB_CLIENT_ID");
  const githubClientSecret = getSecret("GITHUB_CLIENT_SECRET");

  // Admin Local Strategy
  passport.use(
    new LocalStrategy((username, password, done) => {
      if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
        return done(null, {
          id: "admin",
          username: "Super Admin",
          isAdmin: true,
        });
      }
      return done(null, false, { message: "Invalid credentials" });
    }),
  );

  if (githubClientId && githubClientSecret) {
    logger.info("🔑 GitHub OAuth Strategy initialized");
    passport.use(
      new GitHubStrategy(
        {
          clientID: githubClientId,
          clientSecret: githubClientSecret,
          callbackURL: `${process.env.PUBLIC_RELAY_URL}/auth/github/callback`,
        },
        (
          accessToken: string,
          refreshToken: string,
          profile: any,
          done: any,
        ) => {
          return done(null, {
            id: profile.id,
            username: profile.username,
            isAdmin: false,
          });
        },
      ),
    );
  } else {
    logger.warn(
      "⚠️ GitHub OAuth NOT initialized: Missing CLIENT_ID or CLIENT_SECRET",
    );
  }
}

const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
  if (req.isAuthenticated() && req.user) {
    const mfa = await redis.getUserMfa(req.user.id);
    const needsMfa = mfa.totp_enabled || mfa.webauthn_credentials.length > 0;

    if (needsMfa && !(req.session as any).mfa_verified) {
      const isApi =
        req.xhr ||
        req.headers.accept?.includes("application/json") ||
        req.path.startsWith("/api/") ||
        req.path.includes("/tokens") ||
        req.path.includes("/nodes");
      if (isApi) {
        return res
          .status(403)
          .json({
            error: "MFA_REQUIRED",
            message: "MFA verification required",
          });
      }
      return res.status(401).redirect("/mfa-challenge");
    }
    return next();
  }

  const isApi =
    req.xhr ||
    req.headers.accept?.includes("application/json") ||
    req.path.startsWith("/api/") ||
    req.path.includes("/tokens") ||
    req.path.includes("/nodes");
  if (isApi) {
    return res.status(401).json({ error: "UNAUTHORIZED" });
  }
  res.redirect("/login");
};

app.get("/mfa-challenge", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  res.send(`
        <html>
        <head>
            <title>MFA Challenge | Onion-Pipe</title>
            <link rel="icon" href="/logo.png">
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-slate-950 text-slate-100 font-sans min-h-screen flex items-center justify-center">
            <div class="max-w-sm w-full bg-slate-900 p-8 rounded-2xl shadow-2xl border border-slate-800 text-center">
                <div class="flex justify-center mb-6">
                    <img src="/logo.png" class="w-12 h-12 object-contain">
                </div>
                <h1 class="text-2xl font-bold mb-6">Multi-Factor Auth</h1>
                <p class="text-slate-400 text-sm mb-8">Verification required to access your account.</p>
                
                <div id="mfa-options" class="space-y-4">
                    <button id="use-passkey" class="hidden w-full bg-indigo-600 hover:bg-indigo-500 py-3 rounded-lg font-bold transition">
                        Authenticate with Passkey
                    </button>
                    
                    <div id="totp-input" class="hidden">
                        <input type="text" id="otp-code" placeholder="6-digit code" maxlength="6" 
                            onkeyup="if(event.key==='Enter') window.verifyTotp()"
                            class="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 text-center text-2xl font-mono tracking-widest outline-none focus:ring-2 focus:ring-indigo-500 mb-4">
                        <button onclick="window.verifyTotp()" class="w-full bg-slate-800 hover:bg-slate-700 py-3 rounded-lg font-bold border border-slate-700 transition">
                            Verify TOTP
                        </button>
                    </div>
                </div>
            </div>

            <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
            <script>
                const { startAuthentication } = window.SimpleWebAuthnBrowser || {};

                window.showToast = function(message, type = 'indigo') {
                    const toast = document.createElement('div');
                    const icon = type === 'red' ? 'fa-exclamation-circle' : 'fa-check-circle';
                    toast.className = \`fixed bottom-8 left-1/2 -translate-x-1/2 px-6 py-3 rounded-full bg-slate-900 border border-\${type}-500/50 shadow-2xl text-\${type}-400 text-xs font-bold uppercase tracking-widest z-[100] animate-bounce\`;
                    toast.innerHTML = \`<i class="fas \${icon} mr-2"></i> \${message}\`;
                    document.body.appendChild(toast);
                    setTimeout(() => {
                        toast.classList.add('opacity-0', 'transition-opacity', 'duration-500');
                        setTimeout(() => toast.remove(), 500);
                    }, 3000);
                };

                async function checkMfa() {
                    try {
                        const res = await fetch('/api/mfa/status');
                        const status = await res.json();
                        
                        if (status.webauthn) {
                            document.getElementById('use-passkey').classList.remove('hidden');
                            document.getElementById('use-passkey').onclick = verifyPasskey;
                        }
                        if (status.totp) {
                            document.getElementById('totp-input').classList.remove('hidden');
                            document.getElementById('otp-code').focus();
                        }
                    } catch (e) { /* silent fail in production */ }
                }

                async function verifyPasskey() {
                    try {
                        const optRes = await fetch('/api/mfa/webauthn/login/options', { method: 'POST' });
                        const options = await optRes.json();
                        
                        if (!startAuthentication) throw new Error('WebAuthn Browser library not loaded');
                        
                        // Fix: Use optionsJSON as per SimpleWebAuthn v11+ docs
                        const assertion = await startAuthentication({ optionsJSON: options });
                        
                        const verifyRes = await fetch('/api/mfa/webauthn/login/verify', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(assertion)
                        });
                        
                        const result = await verifyRes.json();
                        if (result.verified) {
                            window.location.href = '/dashboard';
                        } else {
                            window.showToast('Authentication failed', 'red');
                        }
                    } catch (err) {
                        if (err.name !== 'AbortError') window.showToast(err.message, 'red');
                    }
                }

                async function verifyTotp() {
                    const code = document.getElementById('otp-code').value;
                    const res = await fetch('/api/mfa/totp/verify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ code })
                    });
                    if (res.ok) window.location.href = '/dashboard';
                    else window.showToast('Invalid code', 'red');
                }

                checkMfa();
            </script>
        </body>
        </html>
    `);
});

const bodyLogger = (req: Request, res: Response, next: NextFunction) => {
  if (IS_MASTER) logger.debug({ path: req.path }, "Request received");
  next();
};

app.use(bodyLogger);

// --- DASHBOARD ROUTES (MASTER ONLY) ---
if (IS_MASTER) {
  logger.info("👑 Master Mode Enabled: Dashboard active at /dashboard");

  app.get("/", (req, res) => {
    const loggedIn = req.isAuthenticated();
    res.send(`
            <html>
            <head>
                <title>Onion-Pipe | Privacy-First Webhook Relay (maintained by Sapphive)</title>
                <meta name="description" content="Securely tunnel webhooks to localhost using the Tor network. Onion-Pipe is an open-source system maintained by the Sapphive Infrastructure Team.">
                <meta name="keywords" content="onion-pipe, tor, webhook relay, tunnel, localhost, privacy, security, sapphive">
                
                <!-- Open Graph / Facebook -->
                <meta property="og:type" content="website">
                <meta property="og:url" content="https://onion-pipe.sapphive.com">
                <meta property="og:title" content="Onion-Pipe | Secure Webhook Tunnels">
                <meta property="og:description" content="Open-source anonymous and secure webhook delivery to your local machine via Tor.">
                <meta property="og:image" content="https://raw.githubusercontent.com/SAPPHIVE/onion-pipe-relay/main/src/assets/logo/logo.png">

                <!-- Twitter -->
                <meta property="twitter:card" content="summary">
                <meta property="twitter:url" content="https://onion-pipe.sapphive.com">
                <meta property="twitter:title" content="Onion-Pipe | Secure Webhook Tunnels">
                <meta property="twitter:description" content="Protect your local dev environment with E2E encrypted webhook tunnels over Tor.">
                <meta property="twitter:image" content="https://raw.githubusercontent.com/SAPPHIVE/onion-pipe-relay/main/src/assets/logo/logo.png">

                <link rel="icon" href="/logo.png">
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-slate-900 text-slate-100 font-sans min-h-screen flex items-center justify-center">
                <div class="max-w-md w-full bg-slate-800 p-8 rounded-xl shadow-2xl border border-slate-700 text-center">
                    <div class="flex justify-center mb-6">
                        <div class="bg-indigo-500/20 p-4 rounded-full">
                            <img src="/logo.png" class="w-16 h-16 object-contain">
                        </div>
                    </div>
                    <h1 class="text-3xl font-bold mb-2">Onion-Pipe</h1>
                    <p class="text-slate-400 mb-8 text-sm uppercase tracking-widest text-xs">Community Relay Network</p>
                    
                    <div class="space-y-4">
                        <div class="p-3 bg-slate-900/50 rounded-lg border border-slate-700">
                            <p class="text-xs text-slate-500 mb-1">Network Status</p>
                            <p class="text-green-400 font-mono text-lg">● ONLINE & ACTIVE</p>
                        </div>
                        
                        <div class="pt-4">
                            <a href="${loggedIn ? "/dashboard" : "/login"}" 
                               class="block w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-3 rounded-lg transition duration-200">
                               ${loggedIn ? "Go to Dashboard" : "Member Access"}
                            </a>
                        </div>
                    </div>

                    <p class="mt-8 text-xs text-slate-500">
                        Join the network (CLI): <br/>
                        <code class="bg-black/50 px-2 py-1 rounded text-indigo-300">onion-pipe register &lt;service-id&gt;</code>
                        <span class="block mt-1 text-[10px] opacity-70 italic text-slate-400">Provide the ID only, omitting .onion</span>
                    </p>
                </div>
            </body>
            </html>
        `);
  });

  app.get("/login", (req, res) => {
    if (req.isAuthenticated()) return res.redirect("/dashboard");
    res.send(`
            <html>
            <head>
                <title>Login | Onion-Pipe Secure Access</title>
                <meta name="description" content="Sign in to the Onion-Pipe dashboard to manage secure tunnels and API keys.">
                <meta property="og:title" content="Login | Onion-Pipe">
                <meta property="og:image" content="https://raw.githubusercontent.com/SAPPHIVE/onion-pipe-relay/main/src/assets/logo/logo.png">
                <link rel="icon" href="/logo.png">
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-slate-950 text-slate-100 font-sans min-h-screen flex items-center justify-center">
                <div class="max-w-sm w-full bg-slate-900 p-8 rounded-2xl shadow-2xl border border-slate-800">
                    <div class="flex justify-center mb-6">
                        <img src="/logo.png" class="w-12 h-12 object-contain">
                    </div>
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
                            ${req.query.error ? '<p class="text-red-400 text-sm text-center">Invalid credentials</p>' : ""}
                        </form>
                    </div>
                </div>
            </body>
            </html>
        `);
  });

  app.get(
    "/auth/github",
    passport.authenticate("github", { scope: ["user:email"] }),
  );

  app.get(
    "/auth/github/callback",
    passport.authenticate("github", { failureRedirect: "/login" }),
    async (req, res) => {
      const isCli = (req.session as any).isCliAuth;
      if (isCli) {
        delete (req.session as any).isCliAuth;
        return res.redirect("/cli-auth");
      }

      // Check if MFA is required
      if (req.user) {
        // EMERGENCY BYPASS FOR LOCKOUT (Temporary)
        if (
          req.user.id === "admin" &&
          process.env.BYPASS_ADMIN_MFA === "true"
        ) {
          console.warn(
            "⚠️ EMERGENCY: Bypassing MFA for admin due to BYPASS_ADMIN_MFA=true",
          );
          (req.session as any).mfa_verified = true;
          return res.redirect("/dashboard");
        }

        const mfa = await redis.getUserMfa(req.user.id);
        if (mfa.totp_enabled || mfa.webauthn_credentials.length > 0) {
          return res.redirect("/mfa-challenge");
        }
      }

      res.redirect("/dashboard");
    },
  );

  app.get("/logout", (req, res) => {
    req.session.destroy(() => {
      res.clearCookie("op-sid");
      res.clearCookie("auth_admin");
      res.redirect("/");
    });
  });

  app.use("/api/mfa", setupMfaRoutes(redis));

  app.get("/cli-auth", requireAuth, async (req, res) => {
    const isAdmin = req.user?.isAdmin;
    if (isAdmin) return res.send("Admin cannot use CLI auth codes.");

    const user = req.user as PassportUser;
    const code = await redis.createAuthCode(user.id);

    res.send(`
            <html>
            <head>
                <title>CLI Authentication | Onion-Pipe</title>
                <link rel="icon" href="/logo.png">
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-slate-950 text-slate-100 font-sans min-h-screen flex items-center justify-center">
                <div class="max-w-md w-full bg-slate-900 p-8 rounded-2xl shadow-2xl border border-slate-800 text-center">
                    <div class="flex justify-center mb-6">
                        <img src="/logo.png" class="w-12 h-12 object-contain">
                    </div>
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

  app.post("/auth/cli/exchange", async (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Code required" });

    const apiKey = await redis.exchangeAuthCode(code);
    if (!apiKey)
      return res.status(401).json({ error: "Invalid or expired code" });

    res.json({ api_key: apiKey });
  });

  app.post(
    "/login",
    passport.authenticate("local", { failureRedirect: "/login?error=1" }),
    async (req, res) => {
      // Check if MFA is required for admin
      if (req.user) {
        // EMERGENCY BYPASS FOR LOCKOUT (Temporary)
        if (
          req.user.id === "admin" &&
          process.env.BYPASS_ADMIN_MFA === "true"
        ) {
          console.warn(
            "⚠️ EMERGENCY: Bypassing MFA for admin due to BYPASS_ADMIN_MFA=true",
          );
          (req.session as any).mfa_verified = true;
          return res.redirect("/dashboard");
        }

        const mfa = await redis.getUserMfa(req.user.id);
        if (mfa.totp_enabled || mfa.webauthn_credentials.length > 0) {
          return res.redirect("/mfa-challenge");
        }
      }
      res.redirect("/dashboard");
    },
  );

  app.get("/logout", (req, res) => {
    req.logout(() => {
      res.clearCookie("op-sid");
      res.redirect("/");
    });
  });

  app.get("/dashboard", requireAuth, async (req, res) => {
    const isAdmin = req.user?.isAdmin;
    const user = req.user as PassportUser;
    const username = isAdmin ? "Super Admin" : user.username;
    const apiKey = !isAdmin ? await redis.getOrCreateUserApiKey(user.id) : null;

    res.send(`
            <html>
            <head>
                <title>Dashboard | Onion-Pipe Management (maintained by Sapphive)</title>
                <meta name="description" content="Manage your anonymous webhook tunnels, rotate API keys, and configure Multi-Factor Authentication.">
                <meta property="og:title" content="Dashboard | Onion-Pipe">
                <meta property="og:image" content="https://raw.githubusercontent.com/SAPPHIVE/onion-pipe-relay/main/src/assets/logo/logo.png">
                <link rel="icon" href="/logo.png">
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-slate-950 text-slate-100 font-sans" data-is-admin="${isAdmin}">
                <nav class="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
                    <div class="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center">
                        <div class="flex items-center space-x-2">
                            <img src="/logo.png" class="w-8 h-8 object-contain">
                            <span class="font-bold tracking-tight">Onion-Pipe Dashboard</span>
                        </div>
                        <div class="flex items-center space-x-4">
                            <span class="text-slate-400 text-sm italic">Logged in as ${username}</span>
                            <a href="/logout" class="bg-slate-800 hover:bg-slate-700 px-4 py-1.5 rounded-lg text-sm font-medium transition">Sign Out</a>
                        </div>
                    </div>
                </nav>

                <main class="max-w-7xl mx-auto px-4 py-8">
                    ${
                      !isAdmin
                        ? `
                    <div class="bg-indigo-600/10 border border-indigo-500/30 p-4 rounded-xl mb-8 flex items-center justify-between">
                        <div class="flex-1">
                            <p class="text-[10px] uppercase font-bold text-indigo-400 mb-1">Your Account API Key (Secret)</p>
                            <div class="flex items-center space-x-3">
                                <div class="relative flex items-center bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
                                    <code id="api-key-text" data-key="${apiKey}" class="text-indigo-200 font-mono text-sm" style="-webkit-text-security: disc;">${apiKey}</code>
                                    <button onclick="window.toggleApiKey()" class="ml-2 text-slate-500 hover:text-indigo-400 transition" title="Reveal API Key">
                                        <svg id="eye-icon" xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                        </svg>
                                    </button>
                                </div>
                                <div class="flex space-x-2">
                                    <button onclick="window.copyApiKey()" class="p-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-400 hover:text-white transition" title="Copy to Clipboard">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 012-2v-8a2 2 0 01-2-2h-8a2 2 0 01-2 2v8a2 2 0 012 2z" />
                                        </svg>
                                    </button>
                                    <button onclick="window.rotateApiKey()" class="p-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-400 hover:text-white transition" title="Rotate/Refresh Key">
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
                    `
                        : ""
                    }

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
                            <p class="text-lg font-mono truncate text-indigo-400">${process.env.PUBLIC_RELAY_URL?.replace("https://", "") || "local"}</p>
                        </div>
                    </div>

                    <!-- MFA Settings (Global) -->
                    <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg mb-8">
                        <div class="px-6 py-4 border-b border-slate-800 bg-emerald-500/5">
                            <h2 class="font-bold text-lg">Identity Security (MFA)</h2>
                        </div>
                        <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                            <!-- WebAuthn -->
                            <div class="bg-slate-950 p-5 rounded-xl border border-slate-800">
                                <div class="flex items-center justify-between mb-4">
                                    <h3 class="font-bold text-indigo-400">Passkeys</h3>
                                    <span id="passkey-status" class="text-[10px] uppercase font-bold px-2 py-0.5 rounded">Checking...</span>
                                </div>
                                <div id="passkey-actions">
                                    <button onclick="window.setupPasskey()" class="w-full bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 py-2 rounded-lg text-xs font-bold transition mb-2">Register New Passkey</button>
                                </div>
                            </div>

                            <!-- TOTP -->
                            <div class="bg-slate-950 p-5 rounded-xl border border-slate-800">
                                <div class="flex items-center justify-between mb-4">
                                    <h3 class="font-bold text-indigo-400">Authenticator App</h3>
                                    <span id="totp-status" class="text-[10px] uppercase font-bold px-2 py-0.5 rounded">Checking...</span>
                                </div>
                                <p class="text-xs text-slate-500 mb-4 h-8">Use apps like Google Authenticator or Authy.</p>
                                <div id="totp-actions">
                                    <button onclick="window.setupTotp()" class="w-full bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 py-2 rounded-lg text-xs font-bold transition">Setup TOTP</button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- TOTP Setup Modal -->
                    <div id="totp-modal" class="hidden fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
                        <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl max-w-sm w-full text-center">
                            <h3 class="text-xl font-bold mb-4">Setup Authenticator</h3>
                            <div id="qrcode-container" class="bg-white p-4 rounded-xl inline-block mb-4"></div>
                            <p class="text-xs text-slate-400 mb-6">Scan this QR code with your app, then enter the 6-digit code below.</p>
                            <input type="text" id="setup-otp" placeholder="000 000" 
                                onkeyup="if(event.key==='Enter') window.verifySetupTotp()"
                                class="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-center text-2xl font-mono tracking-widest outline-none focus:ring-2 focus:ring-indigo-500 mb-4">
                            <div class="flex space-x-3">
                                <button onclick="window.closeTotpModal()" class="flex-1 bg-slate-800 hover:bg-slate-700 py-2 rounded-lg text-sm font-bold transition">Cancel</button>
                                <button onclick="window.verifySetupTotp()" class="flex-1 bg-indigo-600 hover:bg-indigo-500 py-2 rounded-lg text-sm font-bold transition">Verify</button>
                            </div>
                        </div>
                    </div>

                    ${
                      isAdmin
                        ? `
                    <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg mb-8">
                        <div class="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-indigo-500/5">
                            <h2 class="font-bold text-lg">Infrastructure Telemetry (Admin Only)</h2>
                            <button onclick="window.refreshNodes()" class="text-xs bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5 rounded-md transition font-medium uppercase tracking-wider">Refresh Bridges</button>
                        </div>
                        <div class="p-6">
                            <pre id="nodes" class="bg-slate-950 p-4 rounded-xl border border-slate-800 overflow-x-auto text-indigo-400 text-sm font-mono min-h-[100px]">Loading bridge telemetry...</pre>
                        </div>
                    </div>
                    `
                        : ""
                    }

                    <div class="bg-slate-900 border border-slate-800 rounded-2xl shadow-lg">
                        <div class="px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                            <h2 class="font-bold text-lg">${isAdmin ? "All Registered Hooks" : "Your Managed Hooks"}</h2>
                            <div class="flex space-x-2">
                                ${!isAdmin ? `<button onclick="window.showAddHook()" class="text-xs bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5 rounded-md transition font-medium uppercase tracking-wider">+ Add New Hook</button>` : ""}
                                <button onclick="window.refreshTokens()" class="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-md transition font-medium uppercase tracking-wider">Refresh Hooks</button>
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
                                <button onclick="window.showAddHook(false)" class="text-xs text-slate-400 hover:text-white transition">Cancel</button>
                                <button onclick="window.submitNewHook()" class="bg-indigo-600 hover:bg-indigo-500 px-4 py-2 rounded text-xs font-bold transition">Create Hook</button>
                            </div>
                        </div>

                        <div class="p-6">
                            <div id="tokens-list" class="space-y-4">
                                <p class="text-slate-500 italic text-center py-10">Fetching your registered services...</p>
                            </div>
                        </div>
                    </div>
                </main>

                <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
                <script>
                    (function() {
                        const { startRegistration } = window.SimpleWebAuthnBrowser || {};
                        const isAdmin = document.body.dataset.isAdmin === 'true';

                        window.refreshMfaStatus = async function() {
                            try {
                                const res = await fetch('/api/mfa/status');
                                const data = await res.json();
                                const pk = document.getElementById('passkey-status');
                                const tp = document.getElementById('totp-status');
                                if (pk) pk.innerText = data.webauthn ? 'ACTIVE' : 'NOT SET';
                                if (tp) tp.innerText = data.totp ? 'ENABLED' : 'DISABLED';

                                const pkActions = document.getElementById('passkey-actions');
                                if (pkActions) {
                                    pkActions.innerHTML = \`
                                        <button onclick="window.setupPasskey()" class="w-full bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 py-2 rounded-lg text-xs font-bold transition mb-2">Register New Passkey</button>
                                        \${data.webauthn ? \`<button onclick="window.disablePasskey()" class="w-full text-red-500/50 hover:text-red-500 py-1 text-[10px] font-bold transition">Clear All Passkeys</button>\` : ''}
                                    \`;
                                }

                                const tpActions = document.getElementById('totp-actions');
                                if (tpActions) {
                                    tpActions.innerHTML = data.totp 
                                        ? \`<button onclick="window.disableTotp()" class="w-full bg-red-500/10 hover:bg-red-500/20 text-red-400 py-2 rounded-lg text-xs font-bold transition">Disable Authenticator</button>\`
                                        : \`<button onclick="window.setupTotp()" class="w-full bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 py-2 rounded-lg text-xs font-bold transition">Setup TOTP</button>\`;
                                }
                            } catch (e) { /* silent fail */ }
                        };

                        window.disableTotp = async function() {
                            if (!await window.confirmModal('Disable Security', 'Are you sure you want to disable the Authenticator App?')) return;
                            await fetch('/api/mfa/totp/disable', { method: 'POST' });
                            window.refreshMfaStatus();
                            window.showToast('Authenticator Disabled', 'red');
                        };

                        window.disablePasskey = async function() {
                            if (!await window.confirmModal('Remove Passkeys', 'Are you sure you want to clear all registered Passkeys?')) return;
                            await fetch('/api/mfa/webauthn/disable', { method: 'POST' });
                            window.refreshMfaStatus();
                            window.showToast('Passkeys Cleared', 'red');
                        };

                        window.setupPasskey = async function() {
                            if (!startRegistration) return window.showToast('WebAuthn failed to load', 'red');
                            try {
                                const res = await fetch('/api/mfa/webauthn/register/options', { method: 'POST' });
                                const options = await res.json();
                                
                                // Fix: Use optionsJSON as per SimpleWebAuthn v11+ docs
                                const attestation = await startRegistration({ optionsJSON: options });
                                
                                await fetch('/api/mfa/webauthn/register/verify', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify(attestation)
                                });
                                window.showToast('Passkey registered!');
                                window.refreshMfaStatus();
                            } catch (e) { window.showToast(e.message, 'red'); }
                        };

                        window.setupTotp = async function() {
                            const res = await fetch('/api/mfa/totp/setup', { method: 'POST' });
                            const data = await res.json();
                            document.getElementById('qrcode-container').innerHTML = '<img src="' + data.qr + '" class="w-48 h-48 mx-auto">';
                            document.getElementById('totp-modal').classList.remove('hidden');
                        };

                        window.closeTotpModal = function() { document.getElementById('totp-modal').classList.add('hidden'); };

                        window.verifySetupTotp = async function() {
                            const code = document.getElementById('setup-otp').value;
                            const res = await fetch('/api/mfa/totp/verify', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ code, isSetup: true })
                            });
                            const data = await res.json();
                            if (data.verified) {
                                window.showToast('TOTP enabled!');
                                window.closeTotpModal();
                                window.refreshMfaStatus();
                            } else window.showToast('Invalid code', 'red');
                        };

                        window.refreshNodes = async function() {
                            const pre = document.getElementById('nodes');
                            if (!pre) return;
                            try {
                                const res = await fetch('/dashboard/nodes');
                                const data = await res.json();
                                pre.innerText = JSON.stringify(data, null, 2);
                            } catch (e) { pre.innerText = "Error: " + e.message; }
                        };

                        window.refreshTokens = async function() {
                            const list = document.getElementById('tokens-list');
                            if (!list) return;
                            try {
                                const res = await fetch('/dashboard/tokens');
                                const data = await res.json();
                                
                                const apiKey = document.getElementById('api-key-text')?.dataset.key || '<your-api-key>';
                                const relayUrl = window.location.origin;

                                let setupHtml = '';
                                if (!isAdmin) {
                                    setupHtml = \`
                                        <div id="quick-setup-container" class="\${data.length > 0 ? 'mb-8' : 'mb-12 text-left'}">
                                            <details \${data.length === 0 ? 'open' : ''} class="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl group">
                                                <summary class="bg-indigo-500/10 px-6 py-4 border-b border-slate-800 flex justify-between items-center cursor-pointer hover:bg-indigo-500/20 transition-colors list-none">
                                                    <div class="flex items-center space-x-3">
                                                        <h3 class="text-sm font-bold text-indigo-300 uppercase tracking-widest">Quick Setup Guide</h3>
                                                        \${data.length === 0 ? '<span class="px-2 py-0.5 bg-indigo-500 text-[10px] font-bold rounded animate-pulse">RECOMMENDED</span>' : ''}
                                                    </div>
                                                    <div class="flex items-center space-x-4">
                                                        <div class="flex items-center space-x-2 bg-black/40 px-3 py-1 rounded border border-slate-800">
                                                            <code class="text-[10px] text-indigo-400 font-mono italic">\${relayUrl}</code>
                                                        </div>
                                                        <svg class="w-4 h-4 text-slate-500 group-open:rotate-180 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                                                        </svg>
                                                    </div>
                                                </summary>
                                                <div class="p-6 space-y-8 text-left">
                                                    <div>
                                                        <h4 class="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">…or create a new tunnel on the command line</h4>
                                                        <div class="bg-slate-900/50 rounded-2xl p-6 font-mono text-sm text-slate-300 border border-slate-800/50 leading-relaxed shadow-inner">
                                                            <div class="mb-6">
                                                                <p class="text-indigo-400/60 text-[10px] uppercase font-bold tracking-widest mb-2 flex items-center">
                                                                    <span class="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                                                                    Step 0: CLI Login (Optional)
                                                                </p>
                                                                <div onclick="window.copySnippet(this)" class="bg-black/40 border border-slate-800 rounded-xl p-4 text-xs text-indigo-100/80 hover:border-indigo-500/30 transition-colors select-all cursor-pointer">
                                                                    docker run -it --rm <span class="text-indigo-400 font-bold">sapphive/onion-pipe</span> login
                                                                </div>
                                                                <p class="mt-2 text-[10px] text-slate-500 italic leading-tight">
                                                                    Authorizes your terminal and provides a pre-filled deployment command.
                                                                </p>
                                                            </div>

                                                            <div class="mb-6">
                                                                <p class="text-indigo-400/60 text-[10px] uppercase font-bold tracking-widest mb-2 flex items-center">
                                                                    <span class="w-2 h-2 bg-indigo-500 rounded-full mr-2 animate-pulse"></span>
                                                                    Step 1: Key Initialization
                                                                </p>
                                                                <div onclick="window.copySnippet(this)" class="bg-black/40 border border-slate-800 rounded-xl p-4 text-xs text-indigo-100/80 hover:border-indigo-500/30 transition-colors select-all cursor-pointer">
                                                                    docker run --rm -v ./registration:/registration <span class="text-indigo-400 font-bold">sapphive/onion-pipe</span> init
                                                                </div>
                                                            </div>
                                                            
                                                            <div class="mb-6">
                                                                <p class="text-indigo-400/60 text-[10px] uppercase font-bold tracking-widest mb-2 flex items-center">
                                                                    <span class="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                                                                    Step 2: Deployment (Single Line)
                                                                </p>
                                                                <div onclick="window.copySnippet(this)" class="bg-black/40 border border-slate-800 rounded-xl p-4 text-[11px] text-indigo-100/80 break-all select-all cursor-pointer hover:border-indigo-500/30 transition-colors">
                                                                    docker run -d --name onion-pipe -v ./registration:/registration -v ./onion_id:/var/lib/tor/hidden_service -e API_TOKEN="<span class="text-white font-bold">\${apiKey}</span>" -e FORWARD_DEST="http://host.docker.internal:8080" <span class="text-indigo-400 font-bold">sapphive/onion-pipe</span>
                                                                </div>
                                                                <p class="mt-2 text-[10px] text-slate-500 italic leading-tight">
                                                                    Note: FORWARD_DEST should point to your local application endpoint (e.g., localhost:8080) or another Docker container's name/IP if your app is also containerized.
                                                                </p>
                                                            </div>

                                                            <div class="mb-6">
                                                                <p class="text-indigo-400/60 text-[10px] uppercase font-bold tracking-widest mb-2 flex items-center">
                                                                    <span class="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                                                                    Alternative: Docker Compose
                                                                </p>
                                                                <div onclick="window.copySnippet(this)" class="bg-black/40 border border-slate-800 rounded-xl p-4 overflow-x-auto text-[11px] leading-relaxed text-indigo-100/80 hover:border-indigo-500/30 transition-colors select-all cursor-pointer font-mono">
                                                                    <div><span class="text-indigo-400">services:</span></div>
                                                                    <div>&nbsp;&nbsp;<span class="text-indigo-400">onion-pipe:</span></div>
                                                                    <div>&nbsp;&nbsp;&nbsp;&nbsp;<span class="text-indigo-400">image:</span> sapphive/onion-pipe</div>
                                                                    <div>&nbsp;&nbsp;&nbsp;&nbsp;<span class="text-indigo-400">container_name:</span> onion-pipe</div>
                                                                    <div>&nbsp;&nbsp;&nbsp;&nbsp;<span class="text-indigo-400">restart:</span> unless-stopped</div>
                                                                    <div>&nbsp;&nbsp;&nbsp;&nbsp;<span class="text-indigo-400">volumes:</span></div>
                                                                    <div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- ./registration:/registration</div>
                                                                    <div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- ./onion_id:/var/lib/tor/hidden_service</div>
                                                                    <div>&nbsp;&nbsp;&nbsp;&nbsp;<span class="text-indigo-400">environment:</span></div>
                                                                    <div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="text-indigo-400">API_TOKEN:</span> "<span class="text-white font-bold">\${apiKey}</span>"</div>
                                                                    <div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="text-indigo-400">FORWARD_DEST:</span> http://host.docker.internal:8080</div>
                                                                </div>
                                                                <p class="mt-2 text-[10px] text-slate-500 italic leading-tight">
                                                                    Note: FORWARD_DEST should point to your local application endpoint or another Docker container's name/IP if your app is containerized.
                                                                </p>
                                                            </div>
                                                            
                                                            <div>
                                                                <p class="text-indigo-400/60 text-[10px] uppercase font-bold tracking-widest mb-2 flex items-center">
                                                                    <span class="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                                                                    Step 3: Verification
                                                                </p>
                                                                <div onclick="window.copySnippet(this)" class="bg-black/40 border border-slate-800 rounded-xl p-4 text-xs text-indigo-100/80 hover:border-indigo-500/30 transition-colors select-all cursor-pointer">
                                                                    docker logs onion-pipe -f
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    <div>
                                                        <h4 class="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">…or register manually (if auto-reg failed)</h4>
                                                        <div class="bg-slate-900/50 rounded-2xl p-6 font-mono text-xs text-slate-300 border border-slate-800/50 leading-relaxed shadow-inner">
                                                            <p class="text-indigo-400/60 text-[10px] uppercase font-bold tracking-widest mb-2 flex items-center">
                                                                <span class="w-1.5 h-1.5 bg-slate-500 rounded-full mr-2"></span>
                                                                Manual Registration Trigger
                                                            </p>
                                                            <div onclick="window.copySnippet(this)" class="bg-black/40 border border-slate-800 rounded-xl p-4 text-[11px] text-indigo-100/80 select-all cursor-pointer hover:border-indigo-500/30 transition-colors">
                                                                docker exec onion-pipe <span class="text-indigo-400 font-bold">/usr/local/bin/entrypoint.sh register</span>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    <div class="pt-4 border-t border-slate-800/50 flex items-center justify-between">
                                                        <p class="text-[10px] text-slate-500 italic">
                                                            <span class="text-indigo-400 font-bold">ProTip!</span> Mount a permanent volume to keep your .onion address forever.
                                                        </p>
                                                        <a href="https://hub.docker.com/r/sapphive/onion-pipe" target="_blank" class="text-[10px] text-indigo-400 hover:underline font-bold uppercase tracking-tighter">View Docker Hub →</a>
                                                    </div>
                                                </div>
                                            </details>
                                        </div>
                                    \`;
                                }

                                if (!data.length) {
                                    list.innerHTML = \`
                                        <div class="text-center py-6">
                                            <div class="mb-12 p-6 bg-amber-500/5 border border-amber-500/20 rounded-xl text-center">
                                                <p class="text-amber-200/70 text-sm">
                                                    <i class="fas fa-info-circle mr-2 text-amber-500"></i> No hooks found. Setup your client below to get started. Your onion address will appear here automatically once connected.
                                                </p>
                                            </div>
                                            \${setupHtml}
                                        </div>
                                    \`;
                                } else {
                                    list.innerHTML = setupHtml + data.map(t => \`
                                        <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 flex justify-between items-center bg-slate-900/40">
                                            <div>
                                                <code class="text-indigo-400 text-xs font-bold">\${t.token}</code>
                                                <p class="text-slate-300 text-sm italic">\${t.metadata?.onion_service_id}.onion</p>
                                            </div>
                                            <button onclick="window.deleteToken('\${t.token}')" class="text-red-500 text-xs font-bold hover:bg-red-500/10 px-2 py-1 rounded transition">DELETE</button>
                                        </div>
                                    \`).join('');
                                }
                            } catch (e) { list.innerText = "Error: " + e.message; }
                        };


                        window.deleteToken = async function(token) {
                            if (!await window.confirmModal('Delete Hook', 'Permanently remove this mapping?')) return;
                            await fetch('/dashboard/tokens/' + token, { method: 'DELETE' });
                            window.refreshTokens();
                            window.showToast('Hook Removed', 'red');
                        };

                        window.toggleApiKey = function() {
                            const el = document.getElementById('api-key-text');
                            el.style.webkitTextSecurity = el.style.webkitTextSecurity === 'disc' ? 'none' : 'disc';
                        };

                        window.showToast = function(message, type = 'indigo') {
                            const toast = document.createElement('div');
                            const icon = type === 'red' ? 'fa-exclamation-circle' : 'fa-check-circle';
                            toast.className = \`fixed bottom-8 left-1/2 -translate-x-1/2 px-6 py-3 rounded-full bg-slate-900 border border-\${type}-500/50 shadow-2xl text-\${type}-400 text-xs font-bold uppercase tracking-widest z-[100] animate-bounce\`;
                            toast.innerHTML = \`<i class="fas \${icon} mr-2"></i> \${message}\`;
                            document.body.appendChild(toast);
                            setTimeout(() => {
                                toast.classList.add('opacity-0', 'transition-opacity', 'duration-500');
                                setTimeout(() => toast.remove(), 500);
                            }, 3000);
                        };

                        window.confirmModal = function(title, message) {
                            return new Promise((resolve) => {
                                const modal = document.createElement('div');
                                modal.className = 'fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-[200]';
                                modal.innerHTML = \`
                                    <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl max-w-sm w-full text-center shadow-2xl animate-in zoom-in-95 duration-200">
                                        <h3 class="text-xl font-bold mb-2">\${title}</h3>
                                        <p class="text-sm text-slate-400 mb-8">\${message}</p>
                                        <div class="flex space-x-3">
                                            <button id="modal-cancel" class="flex-1 bg-slate-800 hover:bg-slate-700 py-2 rounded-lg text-sm font-bold transition">Cancel</button>
                                            <button id="modal-confirm" class="flex-1 bg-indigo-600 hover:bg-indigo-500 py-2 rounded-lg text-sm font-bold transition">Confirm</button>
                                        </div>
                                    </div>
                                \`;
                                document.body.appendChild(modal);
                                modal.querySelector('#modal-cancel').onclick = () => { modal.remove(); resolve(false); };
                                modal.querySelector('#modal-confirm').onclick = () => { modal.remove(); resolve(true); };
                            });
                        };

                        window.copyApiKey = function() {
                            navigator.clipboard.writeText(document.getElementById('api-key-text').getAttribute('data-key'));
                            window.showToast('API Key Copied');
                        };

                        window.copySnippet = function(el) {
                            const text = el.innerText || el.textContent;
                            navigator.clipboard.writeText(text.trim());
                            
                            // Deselect text
                            if (window.getSelection) { window.getSelection().removeAllRanges(); }
                            
                            // Visual feedback
                            const originalBorder = el.style.borderColor;
                            el.style.borderColor = '#6366f1';
                            window.showToast('Snippet Copied');
                            setTimeout(() => { el.style.borderColor = originalBorder; }, 300);
                        };

                        window.rotateApiKey = async function() {
                            if (!await window.confirmModal('Rotate API Key', 'Existing clients will lose access until updated. Continue?')) return;
                            await fetch('/dashboard/api-key/rotate', { method: 'POST' });
                            window.location.reload();
                        };

                        window.showAddHook = function(show = true) {
                            document.getElementById('add-hook-form').classList.toggle('hidden', !show);
                        };

                        window.submitNewHook = async function() {
                            const onion = document.getElementById('new-onion').value.trim();
                            const pubkey = document.getElementById('new-pubkey').value.trim();
                            if (!onion || !pubkey) return window.showToast('Please fill all fields', 'red');
                            const res = await fetch('/register', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ onion_service_id: onion.replace('.onion', ''), public_key: pubkey })
                            });
                            if (res.ok) {
                                window.showToast('Registered!');
                                window.showAddHook(false);
                                window.refreshTokens();
                            }
                        };

                        // Initialize
                        window.refreshMfaStatus();
                        window.refreshTokens();
                        if (isAdmin) window.refreshNodes();
                    })();
                </script>
            </body>
            </html>
        `);
  });

  app.get("/dashboard/nodes", requireAuth, async (req, res) => {
    if (!req.user?.isAdmin)
      return res.status(401).json({ error: "Admin only" });
    const bridges = await redis.getHealthyBridges();
    res.json(bridges);
  });

  app.get("/dashboard/tokens", requireAuth, async (req, res) => {
    const isAdmin = req.user?.isAdmin;
    const user = req.user as PassportUser;

    if (isAdmin) {
      const tokens = await redis.getAllTokens();
      return res.json(tokens);
    } else {
      const tokens = await redis.getUserTokens(user.id);
      return res.json(tokens);
    }
  });

  app.post("/dashboard/api-key/rotate", requireAuth, async (req, res) => {
    const isAdmin = req.user?.isAdmin;
    if (isAdmin) return res.status(400).json({ error: "Admin has no API key" });

    const user = req.user as PassportUser;
    const newKey = await redis.rotateUserApiKey(user.id);
    res.json({ api_key: newKey });
  });

  app.delete("/dashboard/tokens/:token", requireAuth, async (req, res) => {
    const isAdmin = req.user?.isAdmin;
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

app.get("/health", (req, res) => res.status(200).send("OK"));

// --- GLOBAL ERROR HANDLER ---
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  logger.error(
    { err: err.message, stack: err.stack },
    "Unhandled Server Error",
  );
  res.status(500).send("Internal Server Error: check relay logs");
});

const wss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws, req) => {
  const bridgeId = uuidv4();
  logger.info({ bridgeId }, "Bridge connected");
  bridgeConnections.set(bridgeId, ws);

  ws.on("message", async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === "heartbeat") {
        await redis.updateBridgeHeartbeat({
          bridge_id: bridgeId,
          load: msg.load || 0,
          uptime: msg.uptime || 0,
          last_seen: Date.now(),
        });
      }
    } catch (e) {
      /* ignore malformed heartbeat */
    }
  });

  ws.on("close", () => {
    logger.warn({ bridgeId }, "Bridge disconnected");
    bridgeConnections.delete(bridgeId);
  });
});

app.post("/register", async (req, res) => {
  const {
    onion_service_id,
    public_key,
    registration_secret,
    github_id,
    token: apiKey,
  } = req.body;

  if (!public_key) {
    return res
      .status(400)
      .json({
        error:
          "MISSING_PUBLIC_KEY: End-to-End Encryption is mandatory. Initialize your keys first.",
      });
  }

  let targetUserId = null;

  // 1. If an API Key (token) is provided, validate it
  if (apiKey) {
    const ownerId = await redis.getUserIdByApiKey(apiKey);
    if (!ownerId) {
      return res.status(401).json({ error: "Invalid User API Token" });
    }
    targetUserId = ownerId;
  }

  // 2. If no API Key, fallback to Registration Secret (Legacy/Anonymous mode)
  if (!targetUserId && IS_MASTER && process.env.REGISTRATION_SECRET) {
    if (registration_secret !== process.env.REGISTRATION_SECRET) {
      return res
        .status(403)
        .json({
          error: "Unauthorized registration: Please provide a valid API Token",
        });
    }
  }

  const token = uuidv4();
  const metadata: TokenMetadata = {
    onion_service_id,
    public_key,
    status: "active",
    created_at: Math.floor(Date.now() / 1000).toString(),
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

  logger.info(
    { token, onion_service_id, userId: metadata.github_id },
    "New client registered",
  );
  res.json({
    token,
    relay_url: process.env.PUBLIC_RELAY_URL || `http://localhost:${PORT}`,
  });
});

app.post("/h/:token", async (req, res) => {
  const { token } = req.params;
  try {
    const metadata = await redis.getTokenMetadata(token);
    if (!metadata || metadata.status !== "active") return res.status(404).end();

    if (!metadata.public_key) {
      logger.error({ token }, "Terminal Error: Active hook missing public key");
      return res
        .status(500)
        .json({
          error: "SECURITY_VIOLATION: Missing public key for encryption",
        });
    }

    const payloadToSend = await CryptoService.encrypt(
      JSON.stringify({
        data: req.body,
        timestamp: Date.now(),
        nonce: uuidv4(),
      }),
      metadata.public_key,
    );

    const healthyBridges = await redis.getHealthyBridges();
    const activeIds = healthyBridges
      .map((b) => b.bridge_id)
      .filter((id) => bridgeConnections.has(id));

    if (activeIds.length === 0)
      return res.status(503).json({ error: "No bridges" });

    const selectedId = activeIds[Math.floor(Math.random() * activeIds.length)];
    const ws = bridgeConnections.get(selectedId);

    ws?.send(
      JSON.stringify({
        type: "dispatch",
        onion_service_id: metadata.onion_service_id,
        payload: payloadToSend,
      }),
    );

    res.status(202).json({ status: "dispatched" });
  } catch (err: any) {
    logger.error(
      { err: err.message, stack: err.stack, token },
      "Webhook dispatch failed",
    );
    res
      .status(500)
      .json({ error: "Internal Relay Error", detail: err.message });
  }
});

const server = app.listen(Number(PORT), "0.0.0.0", async () => {
  await redis.connect();
  logger.info(`Relay running on 0.0.0.0:${PORT}`);
});

server.on(
  "upgrade",
  (request: http.IncomingMessage, socket: any, head: Buffer) => {
    wss.handleUpgrade(request, socket, head, (ws) =>
      wss.emit("connection", ws, request),
    );
  },
);
