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

// --- SECURITY HARDENING: Manual Security Headers (Protection without extra dependencies) ---
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // Content Security Policy to prevent XSS
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://unpkg.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; img-src 'self' data: https://raw.githubusercontent.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; connect-src 'self';");
    next();
});

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
      logger.debug({ fp: currentFingerprint }, "New session fingerprint assigned");
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

// Ban Enforcement Middleware
app.use(async (req, res, next) => {
    if (req.isAuthenticated() && req.user) {
        const user = req.user as any;
        // Check ban status for non-admin users
        if (user.id !== 'admin' && !user.isAdmin) {
             const isBanned = await redis.isUserBanned(user.id);
             if (isBanned) {
                 return req.logout(() => {
                     res.clearCookie("op-sid");
                     if (req.xhr || req.path.startsWith("/api/") || req.headers.accept?.includes('json')) {
                         return res.status(403).json({ error: "Your account has been suspended by the administrator." });
                     }
                     return res.redirect("/login?error=banned"); // Assuming login page handles this param
                 });
             }
        }
    }
    next();
});

const bridgeConnections = new Map<string, WebSocket>();
const PORT = process.env.PORT || 3000;

// --- MASTER MODE CONFIG ---
const IS_MASTER = process.env.MASTER === "true";

// Admin credentials cache for high-performance static access
let adminCreds = {
  user: getSecret("ADMIN_USER", "admin"),
  pass: getSecret("ADMIN_PASSWORD", "admin")
};

// Hot-reload trigger for secrets
const reloadAdminSecrets = () => {
    adminCreds.user = getSecret("ADMIN_USER", "admin");
    adminCreds.pass = getSecret("ADMIN_PASSWORD", "admin");
    logger.info("🔐 Super Admin credentials reloaded from secrets files.");
};

// Listen for SIGHUP (standard reload signal) to refresh secrets without restart
process.on('SIGHUP', reloadAdminSecrets);

passport.serializeUser((user: any, done) => done(null, user));
passport.deserializeUser((user: any, done) => done(null, user));

if (IS_MASTER) {
  const githubClientId = getSecret("GITHUB_CLIENT_ID");
  const githubClientSecret = getSecret("GITHUB_CLIENT_SECRET");

  // Admin Local Strategy
  passport.use(
    new LocalStrategy((username, password, done) => {
      logger.debug({ received_user: username, expected_user: adminCreds.user }, "Login attempt check");
      
      if (username === adminCreds.user && password === adminCreds.pass) {
        return done(null, {
          id: "admin",
          username: "Super Admin",
          isAdmin: true,
        });
      }
      logger.warn({ received_user: username }, "Invalid admin login attempt");
      return done(null, false, { message: "Invalid Credentials" });
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
        async (
          accessToken: string,
          refreshToken: string,
          profile: any,
          done: any,
        ) => {
          // Track the user in Redis and save their username
          await redis.saveUsername(profile.id, profile.username);

          // Check if user is banned
          const isBanned = await redis.isUserBanned(profile.id);
          if (isBanned) {
            return done(null, false, { message: "Account Banned" });
          }
          
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
  logger.debug({ path: req.path, auth: req.isAuthenticated(), user: !!req.user }, "requireAuth check");
  if (req.isAuthenticated() && req.user) {
    // SECURITY HARDENING: Check if user was banned while they had an active session
    const isBanned = await redis.isUserBanned(req.user.id);
    if (isBanned) {
      logger.warn({ userId: req.user.id }, "Banned user attempted access with active session. Revoking.");
      return req.logout(() => {
          res.clearCookie("op-sid");
          res.status(403).json({ error: "BANNED", message: "Your account has been suspended." });
      });
    }

    const mfa = await redis.getUserMfa(req.user.id);
    const needsMfa = mfa.totp_enabled || mfa.webauthn_credentials.length > 0;

    if (needsMfa && !(req.session as any).mfa_verified) {
      logger.debug({ user: req.user.id }, "MFA Required but not verified");
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

      // Persist intent for CLI auth redirect after MFA
      if (req.path === "/cli-auth") {
        (req.session as any).isCliAuth = true;
        // Force save session and pass query param
        return req.session.save(() => res.status(401).redirect("/mfa-challenge?cli=true"));
      }
      
      const isCli = (req.session as any).isCliAuth;
      return res.status(401).redirect(`/mfa-challenge${isCli ? '?cli=true' : ''}`);
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

  // Persist intent for CLI auth redirect after login
  if (req.path === "/cli-auth") {
    (req.session as any).isCliAuth = true;
    return req.session.save(() => res.redirect("/login?cli=true"));
  }

  res.redirect("/login");
};

const isAdmin = (req: Request, res: Response, next: NextFunction) => {
    if (req.isAuthenticated() && (req.user as any).isAdmin) {
        return next();
    }
    res.status(403).json({ error: "Access denied" });
};

app.get("/mfa-challenge", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  
  // Sync query param to session if present
  if (req.query.cli === "true") {
      (req.session as any).isCliAuth = true;
      // We don't force save here as we proceed to render immediately
  }

  const isCli = (req.session as any).isCliAuth === true || req.query.cli === "true";
  
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
                const IS_CLI = ${!!isCli};

                window.showToast = function(message, type = 'indigo') {
                    const toast = document.createElement('div');
                    const icon = type === 'red' ? 'fa-exclamation-circle' : 'fa-check-circle';
                    toast.className = 'fixed bottom-8 left-1/2 -translate-x-1/2 px-6 py-3 rounded-full bg-slate-900 border border-' + type + '-500/50 shadow-2xl text-' + type + '-400 text-xs font-bold uppercase tracking-widest z-[100] animate-bounce';
                    toast.innerHTML = '<i class="fas ' + icon + ' mr-2"></i> ' + message;
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
                            window.location.href = IS_CLI ? '/cli-auth' : '/dashboard';
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
                    if (res.ok) window.location.href = IS_CLI ? '/cli-auth' : '/dashboard';
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
                            <p class="text-green-400 font-mono text-lg">● Online & Active</p>
                        </div>
                        
                        <div class="pt-4">
                            <a href="${loggedIn ? "/dashboard" : "/login"}" 
                               class="block w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-3 rounded-lg transition duration-200">
                               ${loggedIn ? "Go to Dashboard" : "Member Access"}
                            </a>
                        </div>
                    </div>

                    <p class="mt-8 text-xs text-slate-500">
                        <span class="block mb-2 text-xs text-slate-500">Authenticate CLI:</span>
                        <code onclick="window.copyLandingSnippet(this)" class="bg-black/50 px-2 py-1 rounded text-indigo-300 font-mono cursor-pointer hover:text-white transition-colors border border-transparent hover:border-indigo-500/30">docker run -it --rm sapphive/onion-pipe login</code>
                        <span class="block mt-1 text-[10px] opacity-70 italic text-slate-400">Sync your account and generate API keys via terminal</span>
                    </p>

                    <script>
                        window.copyLandingSnippet = function(el) {
                            const text = el.innerText || el.textContent;
                            navigator.clipboard.writeText(text.trim());
                            
                            const toast = document.createElement('div');
                            toast.className = 'fixed bottom-8 left-1/2 -translate-x-1/2 px-6 py-3 rounded-full bg-slate-900 border border-indigo-500/50 shadow-2xl text-indigo-400 text-xs font-bold uppercase tracking-widest z-[100] animate-bounce';
                            toast.innerText = 'Snippet Copied';
                            document.body.appendChild(toast);
                            
                            setTimeout(() => {
                                toast.classList.add('opacity-0', 'transition-opacity', 'duration-500');
                                setTimeout(() => toast.remove(), 500);
                            }, 2000);
                        };
                    </script>
                </div>
            </body>
            </html>
        `);
  });

  app.get("/login", (req, res) => {
    // Check for CLI auth intent in session or query param
    const isCli = (req.session as any).isCliAuth === true || req.query.cli === "true";

    const errorHtml = req.query.error === 'banned' 
        ? `<div class="bg-red-500/10 border border-red-500/20 rounded-lg p-4 mb-6 text-center">
             <div class="flex items-center justify-center space-x-2 text-red-500 mb-1">
                <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                <span class="text-sm font-bold uppercase tracking-widest">Account Suspended</span>
             </div>
             <p class="text-xs text-red-400/80 uppercase tracking-tighter leading-tight mx-auto">Contact system administrator.</p>
           </div>`
        : req.query.error === 'hijack'
            ? `<div class="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4 mb-6 text-center">
                 <div class="flex items-center justify-center space-x-2 text-amber-500 mb-1">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                    <span class="text-sm font-bold uppercase tracking-widest">Session Mismatch</span>
                 </div>
                 <p class="text-xs text-amber-400/80 uppercase tracking-tighter leading-tight mx-auto">Security mismatch. Please re-authenticate.</p>
               </div>`
        : req.query.error 
            ? `<p class="text-red-400 text-sm text-center py-2 mb-4 bg-red-500/5 border border-red-500/10 rounded-lg font-medium">Invalid Credentials</p>` 
            : "";

    if (req.isAuthenticated()) {
        if (isCli) {
             return res.redirect("/cli-auth");
        }
        return res.redirect("/dashboard");
    }
    
    // If query param is set but not session, sync them
    if (req.query.cli === "true" && !(req.session as any).isCliAuth) {
        (req.session as any).isCliAuth = true;
        req.session.save((err) => {
            if (err) logger.error(err, "Session save error in /login");
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
                        <a href="/auth/github${isCli ? '?cli=true' : ''}" 
                           class="flex items-center justify-center space-x-3 w-full bg-white hover:bg-slate-100 text-slate-900 py-3 rounded-lg font-bold transition duration-200">
                            <svg xmlns="http://www.w3.org/2000/svg"class="w-6 h-6" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.041-1.416-4.041-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                            <span>Sign in with GitHub</span>
                        </a>`);
        });
        return;
    }

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
                    
                    ${errorHtml}

                    <div class="space-y-4">
                        <a href="/auth/github${isCli ? '?cli=true' : ''}" 
                           class="flex items-center justify-center space-x-3 w-full bg-white hover:bg-slate-100 text-slate-900 py-3 rounded-lg font-bold transition duration-200">
                            <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.041-1.416-4.041-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
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
                        </form>
                    </div>
                </div>
            </body>
            </html>
        `);
  });

  app.get(
    "/auth/github",
    (req, res, next) => {
        if (req.query.cli === 'true') {
            (req.session as any).isCliAuth = true;
            req.session.save(() => next());
        } else {
            next();
        }
    },
    passport.authenticate("github", { scope: ["user:email"] }),
  );

  app.get(
    "/auth/github/callback",
    (req, res, next) => {
        // Backup CLI auth intent before Passport potentially regenerates the session
        if ((req.session as any).isCliAuth) {
            (req as any).wasCliAuth = true;
        }
        next();
    },
    (req, res, next) => {
        passport.authenticate("github", (err: any, user: any, info: any) => {
            if (err) return next(err);
            if (!user) {
                const message = info?.message || "";
                if (message === "Account Banned") {
                    return res.redirect("/login?error=banned");
                }
                return res.redirect("/login?error=true");
            }
            req.logIn(user, (err) => {
                if (err) return next(err);
                next();
            });
        })(req, res, next);
    },
    async (req, res) => {
      // Check if MFA is required FIRST
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
          // Continue to CLI check below
        } else {
          const mfa = await redis.getUserMfa(req.user.id);
          if (mfa.totp_enabled || mfa.webauthn_credentials.length > 0) {
            const isCli = (req.session as any).isCliAuth || (req as any).wasCliAuth;
            
            // Restore session flag if it was lost during regeneration
            if (isCli && !(req.session as any).isCliAuth) {
                (req.session as any).isCliAuth = true;
            }

            return res.redirect(`/mfa-challenge${isCli ? '?cli=true' : ''}`);
          }
        }
      }

      const isCli = (req.session as any).isCliAuth || (req as any).wasCliAuth;
      if (isCli) {
        // Restore session flag if it was lost during regeneration
        if (!(req.session as any).isCliAuth) {
             (req.session as any).isCliAuth = true;
        }
        return req.session.save(() => res.redirect("/cli-auth"));
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
    // Clear the redirect intent flag once reached
    delete (req.session as any).isCliAuth;

    const isAdmin = req.user?.isAdmin;
    if (isAdmin) return res.send("Admin cannot use CLI auth codes.");

    const user = req.user as PassportUser;
    const code = await redis.createAuthCode(user.id);
    
    // Set monitoring key for auto-redirect
    await redis.getClient().set(`cli_status:${code}`, "pending", { EX: 300 });

    res.send(`
            <html>
            <head>
                <title>CLI Authentication | Onion-Pipe</title>
                <link rel="icon" href="/logo.png">
                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-slate-950 text-slate-100 font-sans min-h-screen flex items-center justify-center">
                <div class="max-w-md w-full bg-slate-900 p-8 rounded-2xl shadow-2xl border border-slate-800 text-center">
                    <div class="flex justify-center mb-6">
                        <img src="/logo.png" class="w-12 h-12 object-contain">
                    </div>
                    <h1 class="text-2xl font-bold mb-2">CLI Authentication</h1>
                    <p class="text-slate-500 text-sm mb-8 font-mono uppercase tracking-widest leading-none">Your One-Time Device Code</p>
                    
                    <div onclick="window.copyCode()" class="bg-slate-950 border-2 border-dashed border-indigo-500/50 p-6 rounded-xl mb-6 relative group cursor-pointer hover:border-indigo-400 transition-all duration-200 overflow-hidden active:scale-[0.98]">
                        <span id="auth-code" class="text-5xl font-black font-mono tracking-[0.2em] text-indigo-400 group-hover:text-indigo-300">${code}</span>
                        <div class="absolute inset-0 bg-indigo-500/5 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                            <span class="text-[10px] text-indigo-300 font-bold uppercase tracking-widest bg-slate-900 px-3 py-1 rounded-full border border-indigo-500/30">Click to Copy</span>
                        </div>
                        <div class="absolute -bottom-6 left-0 right-0 text-center">
                             <span id="status-text" class="text-[10px] text-indigo-500/50 animate-pulse">Waiting for terminal...</span>
                        </div>
                    </div>

                    <p class="text-slate-400 text-xs mb-8">Paste this code into your terminal to complete the <code class="bg-black px-1 text-indigo-300">onion-pipe login</code> command.</p>

                    <a href="/dashboard" class="text-slate-500 hover:text-white text-xs underline transition">Go to Dashboard</a>
                </div>
                <script>
                    const CODE = "${code}";

                    window.showToast = function(message, type = 'indigo') {
                        const toast = document.createElement('div');
                        toast.className = 'fixed bottom-8 left-1/2 -translate-x-1/2 px-6 py-3 rounded-full bg-slate-900 border border-' + type + '-500/50 shadow-2xl text-' + type + '-400 text-xs font-bold uppercase tracking-widest z-[100] animate-bounce';
                        toast.innerHTML = '<i class="fas fa-check-circle mr-2"></i> ' + message;
                        document.body.appendChild(toast);
                        setTimeout(() => {
                            toast.classList.add('opacity-0', 'transition-opacity', 'duration-500');
                            setTimeout(() => toast.remove(), 500);
                        }, 3000);
                    };

                    window.copyCode = async () => {
                        try {
                            await navigator.clipboard.writeText(CODE);
                            window.showToast('Auth Code Copied');
                        } catch (err) {
                            console.error('Failed to copy code');
                        }
                    };

                    setInterval(async () => {
                        try {
                            const res = await fetch('/api/cli/status?code=' + CODE);
                            const data = await res.json();
                            if (data.status === 'success') {
                                document.getElementById('status-text').innerText = "Connected! Redirecting...";
                                document.getElementById('status-text').className = "text-[10px] text-green-400 font-bold";
                                setTimeout(() => window.location.href = '/dashboard', 1000);
                            }
                        } catch(e) {}
                    }, 2000);
                </script>
            </body>
            </html>
        `);
  });

  app.get("/api/cli/status", async (req, res) => {
    const code = req.query.code as string;
    if (!code) return res.json({ status: "unknown" });
    const status = await redis.getClient().get(`cli_status:${code}`);
    res.json({ status: status || "unknown" });
  });

  app.post("/auth/cli/exchange", async (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Code required" });

    const apiKey = await redis.exchangeAuthCode(code);
    if (!apiKey)
      return res.status(401).json({ error: "Invalid or expired code" });

    // Mark as success for frontend polling
    await redis.getClient().set(`cli_status:${code}`, "success", { EX: 60 });

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

      const isCli = (req.session as any).isCliAuth;
      if (isCli) {
        return res.redirect("/cli-auth");
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

  // --- Admin API Endpoints ---
  app.get("/dashboard/admin/users", isAdmin, async (req, res) => {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const search = (req.query.search as string) || '';
      const status = (req.query.status as string) || 'all';
      const result = await redis.getPaginatedUsers(page, limit, search, status);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to fetch users: ' + err.message });
    }
  });

  app.post("/dashboard/admin/users/:id/status", isAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        await redis.setUserBanStatus(req.params.id as string, status === 'banned');
        res.json({ success: true });
    } catch (err: any) {
        res.status(500).json({ error: 'Failed to update status: ' + err.message });
    }
  });

  app.delete("/dashboard/admin/users/:id", isAdmin, async (req, res) => {
    try {
      await redis.deleteUser(req.params.id as string);
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to delete user: ' + err.message });
    }
  });

  app.get("/dashboard", requireAuth, async (req, res) => {
    const isAdmin = req.user?.isAdmin;
    const user = req.user as PassportUser;
    const username = isAdmin ? "Super Admin" : user.username;
    const apiKey = !isAdmin ? await redis.getOrCreateUserApiKey(user.id) : null;
    const stats = isAdmin ? await redis.getUserStats() : { total: 0, active: 0, banned: 0 };

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
                            <code onclick="window.copySnippet(this)" class="text-[10px] bg-black/50 px-2 py-1 rounded text-slate-400 font-mono cursor-pointer hover:text-indigo-300 transition-colors border border-transparent hover:border-indigo-500/30">docker run -it --rm sapphive/onion-pipe login</code>
                        </div>
                    </div>
                    `
                        : ""
                    }

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg text-center">
                            <p class="text-slate-500 text-sm mb-1">Network Status</p>
                            <p class="text-2xl font-bold text-green-400">● Active</p>
                        </div>
                        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg text-center">
                            <p class="text-slate-500 text-sm mb-1">Connected Bridges</p>
                            <p class="text-2xl font-bold text-white">${bridgeConnections.size}</p>
                        </div>
                        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg text-center">
                            <p class="text-slate-500 text-sm mb-1">Public Endpoint</p>
                            <p class="text-lg font-mono truncate text-indigo-400">${process.env.PUBLIC_RELAY_URL?.replace("https://", "") || "local"}</p>
                        </div>
                        ${isAdmin ? `
                        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg text-center">
                            <p class="text-slate-500 text-sm mb-1">Total Users</p>
                            <p class="text-2xl font-bold text-indigo-400">${stats?.total}</p>
                        </div>
                        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg text-center">
                            <p class="text-slate-500 text-sm mb-1">Active Users</p>
                            <p class="text-2xl font-bold text-emerald-400">${stats?.active}</p>
                        </div>
                        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg text-center">
                            <p class="text-slate-500 text-sm mb-1">Banned Users</p>
                            <p class="text-2xl font-bold text-rose-400">${stats?.banned}</p>
                        </div>
                        ` : ''}
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

                    <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg mb-8">
                        <div class="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-indigo-500/5">
                            <h2 class="font-bold text-lg">User Management (Admin Only)</h2>
                            <button onclick="window.userManager.fetch()" class="text-xs bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5 rounded-md transition font-medium uppercase tracking-wider">Refresh</button>
                        </div>
                        <div class="p-6">
                            <div class="flex flex-col md:flex-row md:items-center space-y-4 md:space-y-0 md:space-x-4 mb-6">
                                <div class="relative flex-1">
                                    <input type="text" id="user-search" placeholder="Search users by name or ID..." class="w-full bg-slate-950 border border-slate-700 rounded-lg pl-10 pr-12 py-2.5 text-sm outline-none focus:ring-1 focus:ring-indigo-500 transition-all font-medium" onkeyup="window.userManager.debounceSearch(this.value)">
                                    <i class="fas fa-search absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 text-xs"></i>
                                    <button id="user-search-clear" onclick="window.userManager.clearSearch()" class="hidden absolute right-2 top-1/2 -translate-y-1/2 w-8 h-8 flex items-center justify-center bg-slate-800 hover:bg-slate-700 text-indigo-400 rounded-md border border-slate-700/50 transition-all shadow-lg active:scale-95" title="Clear Search">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                                            <path d="M 9.375 11.109375 C 9.539062 11.175781 9.695312 11.253906 9.851562 11.335938 C 9.898438 11.363281 9.945312 11.386719 9.992188 11.410156 C 10.128906 11.480469 10.269531 11.550781 10.40625 11.625 C 10.445312 11.644531 10.480469 11.664062 10.519531 11.683594 C 10.699219 11.777344 10.875 11.871094 11.054688 11.964844 C 11.34375 12.121094 11.636719 12.269531 11.929688 12.421875 C 12.328125 12.628906 12.726562 12.835938 13.125 13.046875 C 13.410156 13.195312 13.695312 13.34375 13.980469 13.492188 C 14.027344 13.519531 14.070312 13.542969 14.117188 13.566406 C 14.253906 13.636719 14.394531 13.710938 14.53125 13.78125 C 14.847656 13.945312 15.164062 14.113281 15.480469 14.277344 C 15.566406 14.320312 15.648438 14.363281 15.734375 14.40625 C 17.078125 15.109375 17.078125 15.109375 17.203125 15.234375 C 17.191406 15.597656 17.078125 15.886719 16.929688 16.21875 C 16.894531 16.296875 16.894531 16.296875 16.859375 16.378906 C 16.320312 17.617188 15.714844 18.824219 15 19.96875 C 14.980469 20.003906 14.957031 20.035156 14.9375 20.070312 C 14.625 20.574219 14.320312 21.023438 13.726562 21.203125 C 12.796875 21.414062 11.679688 20.804688 10.875 20.390625 C 10.78125 20.296875 10.78125 20.296875 10.765625 20.183594 C 10.785156 20.03125 10.828125 19.992188 10.941406 19.890625 C 10.972656 19.863281 11.007812 19.832031 11.042969 19.800781 C 11.078125 19.765625 11.117188 19.734375 11.152344 19.703125 C 11.226562 19.636719 11.300781 19.566406 11.375 19.5 C 11.410156 19.46875 11.445312 19.433594 11.480469 19.402344 C 11.972656 18.945312 12.714844 18.15625 12.851562 17.476562 C 12.84375 17.242188 12.792969 17.152344 12.65625 16.96875 C 12.519531 16.855469 12.367188 16.863281 12.191406 16.859375 C 12.003906 16.890625 11.886719 16.980469 11.769531 17.125 C 11.738281 17.164062 11.710938 17.207031 11.679688 17.25 C 11.648438 17.296875 11.617188 17.34375 11.582031 17.390625 C 11.550781 17.4375 11.519531 17.484375 11.484375 17.53125 C 11.214844 17.921875 10.921875 18.265625 10.59375 18.609375 C 10.558594 18.644531 10.523438 18.683594 10.488281 18.71875 C 10.285156 18.933594 10.066406 19.128906 9.835938 19.316406 C 9.808594 19.339844 9.78125 19.363281 9.753906 19.386719 C 9.570312 19.53125 9.464844 19.570312 9.234375 19.546875 C 9.113281 19.492188 9.113281 19.492188 8.992188 19.414062 C 8.945312 19.386719 8.902344 19.355469 8.855469 19.328125 C 8.78125 19.28125 8.78125 19.28125 8.710938 19.234375 C 8.660156 19.203125 8.613281 19.171875 8.558594 19.136719 C 7.335938 18.351562 7.335938 18.351562 7.171875 18.1875 C 7.171875 18.09375 7.167969 18 7.171875 17.90625 C 7.257812 17.863281 7.339844 17.820312 7.421875 17.78125 C 7.476562 17.753906 7.527344 17.726562 7.582031 17.703125 C 7.671875 17.65625 7.761719 17.613281 7.855469 17.570312 C 8.101562 17.457031 8.3125 17.320312 8.527344 17.15625 C 8.566406 17.128906 8.566406 17.128906 8.605469 17.097656 C 8.789062 16.957031 8.925781 16.820312 8.972656 16.589844 C 8.96875 16.382812 8.953125 16.242188 8.8125 16.078125 C 8.621094 15.941406 8.457031 15.90625 8.230469 15.941406 C 8.019531 16.015625 7.863281 16.160156 7.691406 16.296875 C 7.160156 16.699219 6.503906 16.847656 5.859375 16.96875 C 5.808594 16.976562 5.761719 16.988281 5.710938 17 C 5.421875 16.949219 5.265625 16.746094 5.0625 16.546875 C 5.003906 16.492188 4.941406 16.441406 4.882812 16.390625 C 3.597656 15.265625 3.597656 15.265625 3.546875 14.765625 C 3.53125 14.355469 3.59375 14.101562 3.863281 13.792969 C 4.183594 13.515625 4.464844 13.441406 4.878906 13.347656 C 6.324219 13.003906 7.730469 12.367188 8.824219 11.335938 C 8.855469 11.308594 8.886719 11.277344 8.921875 11.246094 C 8.949219 11.21875 8.976562 11.195312 9.003906 11.167969 C 9.140625 11.082031 9.210938 11.085938 9.375 11.109375 Z M 9.375 11.109375 M 19.742188 2.585938 C 20.148438 2.960938 20.417969 3.488281 20.453125 4.039062 C 20.457031 4.109375 20.457031 4.179688 20.457031 4.25 C 20.457031 4.28125 20.457031 4.3125 20.460938 4.34375 C 20.453125 4.820312 20.25 5.230469 20.035156 5.644531 C 20.011719 5.695312 19.984375 5.746094 19.960938 5.796875 C 19.773438 6.160156 19.585938 6.523438 19.390625 6.886719 C 19.238281 7.175781 19.089844 7.464844 18.9375 7.757812 C 18.855469 7.917969 18.769531 8.082031 18.6875 8.242188 C 18.636719 8.335938 18.589844 8.429688 18.539062 8.523438 C 18.480469 8.640625 18.417969 8.757812 18.359375 8.875 C 18.339844 8.914062 18.320312 8.949219 18.300781 8.984375 C 18.160156 9.253906 18 9.511719 17.828125 9.765625 C 17.757812 9.886719 17.757812 9.886719 17.769531 10.007812 C 17.820312 10.144531 17.878906 10.261719 17.945312 10.390625 C 18.414062 11.300781 18.359375 12.292969 18.054688 13.242188 C 18.015625 13.359375 17.976562 13.476562 17.933594 13.59375 C 17.917969 13.628906 17.90625 13.667969 17.894531 13.707031 C 17.796875 13.953125 17.796875 13.953125 17.667969 14.015625 C 17.460938 14.015625 17.320312 13.925781 17.140625 13.832031 C 17.082031 13.800781 17.082031 13.800781 17.023438 13.773438 C 16.902344 13.707031 16.78125 13.644531 16.65625 13.578125 C 16.578125 13.539062 16.5 13.496094 16.417969 13.453125 C 16.21875 13.351562 16.019531 13.246094 15.824219 13.140625 C 15.625 13.039062 15.429688 12.933594 15.230469 12.828125 C 15.195312 12.808594 15.15625 12.789062 15.121094 12.769531 C 14.835938 12.621094 14.554688 12.476562 14.273438 12.328125 C 13.949219 12.160156 13.625 11.988281 13.300781 11.820312 C 12.9375 11.628906 12.574219 11.4375 12.210938 11.25 C 12.050781 11.167969 11.890625 11.082031 11.726562 11 C 11.632812 10.949219 11.539062 10.902344 11.441406 10.851562 C 10.707031 10.472656 10.707031 10.472656 10.421875 10.300781 C 10.390625 10.28125 10.359375 10.261719 10.328125 10.246094 C 10.265625 10.171875 10.265625 10.171875 10.238281 10.042969 C 10.277344 9.824219 10.398438 9.71875 10.554688 9.5625 C 10.609375 9.507812 10.664062 9.453125 10.71875 9.394531 C 10.757812 9.355469 10.757812 9.355469 10.800781 9.3125 C 10.871094 9.242188 10.933594 9.164062 10.996094 9.085938 C 11.46875 8.527344 12.316406 8.101562 13.03125 7.96875 C 13.105469 7.96875 13.175781 7.96875 13.25 7.96875 C 13.59375 7.972656 13.59375 7.972656 13.921875 7.875 C 14.136719 7.652344 14.230469 7.347656 14.339844 7.0625 C 14.414062 6.878906 14.507812 6.707031 14.605469 6.53125 C 14.644531 6.457031 14.683594 6.382812 14.722656 6.308594 C 14.742188 6.269531 14.765625 6.230469 14.785156 6.1875 C 14.921875 5.925781 15.058594 5.660156 15.195312 5.398438 C 15.246094 5.296875 15.296875 5.195312 15.351562 5.097656 C 15.5 4.804688 15.648438 4.515625 15.796875 4.226562 C 15.839844 4.136719 15.882812 4.050781 15.925781 3.964844 C 15.980469 3.859375 16.035156 3.757812 16.085938 3.652344 C 16.464844 2.914062 16.890625 2.394531 17.691406 2.117188 C 18.402344 1.9375 19.171875 2.125 19.742188 2.585938 Z M 19.742188 2.585938 M 6.109375 7.554688 C 6.355469 7.722656 6.566406 7.917969 6.632812 8.214844 C 6.679688 8.53125 6.636719 8.765625 6.464844 9.035156 C 6.285156 9.265625 6.101562 9.355469 5.820312 9.414062 C 5.507812 9.441406 5.289062 9.375 5.046875 9.179688 C 4.820312 8.960938 4.730469 8.753906 4.714844 8.441406 C 4.722656 8.167969 4.800781 7.957031 4.988281 7.757812 C 5.308594 7.472656 5.710938 7.414062 6.109375 7.554688 Z M 6.109375 7.554688 M 3.664062 10.484375 C 3.898438 10.652344 4.035156 10.824219 4.101562 11.105469 C 4.144531 11.402344 4.09375 11.609375 3.945312 11.871094 C 3.753906 12.109375 3.585938 12.226562 3.28125 12.28125 C 2.964844 12.296875 2.734375 12.226562 2.480469 12.035156 C 2.257812 11.832031 2.191406 11.617188 2.179688 11.320312 C 2.191406 11.039062 2.265625 10.824219 2.457031 10.617188 C 2.804688 10.308594 3.257812 10.25 3.664062 10.484375 Z M 3.664062 10.484375 "/>
                                        </svg>
                                    </button>
                                </div>
                                <div class="flex items-center space-x-2">
                                    <span class="text-[10px] uppercase font-bold text-slate-500 tracking-widest whitespace-nowrap">Filter:</span>
                                    <select onchange="window.userManager.setStatus(this.value)" class="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2.5 text-sm outline-none focus:ring-1 focus:ring-indigo-500 transition-all cursor-pointer">
                                        <option value="all">All Users</option>
                                        <option value="active">Active Only</option>
                                        <option value="banned">Banned Only</option>
                                    </select>
                                </div>
                            </div>
                            <div class="overflow-x-auto">
                                <table class="w-full text-sm text-left">
                                    <thead class="text-xs text-slate-500 uppercase font-bold border-b border-slate-800">
                                        <tr>
                                            <th class="px-4 py-3">GitHub ID</th>
                                            <th class="px-4 py-3">Username</th>
                                            <th class="px-4 py-3 text-center">Hooks</th>
                                            <th class="px-4 py-3 text-center">Status</th>
                                            <th class="px-4 py-3 text-right">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="users-list-body" class="divide-y divide-slate-800">
                                        <tr><td colspan="5" class="px-4 py-10 text-center italic text-slate-500">Loading users...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                            <div class="mt-4 flex justify-between items-center text-xs text-slate-500 border-t border-slate-800 pt-4">
                                <span id="user-pagination-info">Showing users...</span>
                                <div class="flex space-x-2">
                                    <button onclick="window.userManager.prevPage()" class="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded disabled:opacity-50" id="user-prev-btn">Prev</button>
                                    <button onclick="window.userManager.nextPage()" class="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded disabled:opacity-50" id="user-next-btn">Next</button>
                                </div>
                            </div>
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
                                <button onclick="window.tokenManager.fetch()" class="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-md transition font-medium uppercase tracking-wider">Refresh Hooks</button>
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
                            <div class="flex flex-col md:flex-row md:items-center space-y-4 md:space-y-0 md:space-x-4 mb-6">
                                <div class="relative flex-1">
                                    <input type="text" id="token-search" placeholder="${isAdmin ? 'Search hooks by ID or Owner...' : 'Search hooks by ID or Project Name...'}" class="w-full bg-slate-950 border border-slate-700 rounded-lg pl-10 pr-12 py-2.5 text-sm outline-none focus:ring-1 focus:ring-indigo-500 transition-all font-medium" onkeyup="window.tokenManager.debounceSearch(this.value)">
                                    <i class="fas fa-search absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 text-xs"></i>
                                    <button id="token-search-clear" onclick="window.tokenManager.clearSearch()" class="hidden absolute right-2 top-1/2 -translate-y-1/2 w-8 h-8 flex items-center justify-center bg-slate-800 hover:bg-slate-700 text-indigo-400 rounded-md border border-slate-700/50 transition-all shadow-lg active:scale-95" title="Clear Search">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                                            <path d="M 9.375 11.109375 C 9.539062 11.175781 9.695312 11.253906 9.851562 11.335938 C 9.898438 11.363281 9.945312 11.386719 9.992188 11.410156 C 10.128906 11.480469 10.269531 11.550781 10.40625 11.625 C 10.445312 11.644531 10.480469 11.664062 10.519531 11.683594 C 10.699219 11.777344 10.875 11.871094 11.054688 11.964844 C 11.34375 12.121094 11.636719 12.269531 11.929688 12.421875 C 12.328125 12.628906 12.726562 12.835938 13.125 13.046875 C 13.410156 13.195312 13.695312 13.34375 13.980469 13.492188 C 14.027344 13.519531 14.070312 13.542969 14.117188 13.566406 C 14.253906 13.636719 14.394531 13.710938 14.53125 13.78125 C 14.847656 13.945312 15.164062 14.113281 15.480469 14.277344 C 15.566406 14.320312 15.648438 14.363281 15.734375 14.40625 C 17.078125 15.109375 17.078125 15.109375 17.203125 15.234375 C 17.191406 15.597656 17.078125 15.886719 16.929688 16.21875 C 16.894531 16.296875 16.894531 16.296875 16.859375 16.378906 C 16.320312 17.617188 15.714844 18.824219 15 19.96875 C 14.980469 20.003906 14.957031 20.035156 14.9375 20.070312 C 14.625 20.574219 14.320312 21.023438 13.726562 21.203125 C 12.796875 21.414062 11.679688 20.804688 10.875 20.390625 C 10.78125 20.296875 10.78125 20.296875 10.765625 20.183594 C 10.785156 20.03125 10.828125 19.992188 10.941406 19.890625 C 10.972656 19.863281 11.007812 19.832031 11.042969 19.800781 C 11.078125 19.765625 11.117188 19.734375 11.152344 19.703125 C 11.226562 19.636719 11.300781 19.566406 11.375 19.5 C 11.410156 19.46875 11.445312 19.433594 11.480469 19.402344 C 11.972656 18.945312 12.714844 18.15625 12.851562 17.476562 C 12.84375 17.242188 12.792969 17.152344 12.65625 16.96875 C 12.519531 16.855469 12.367188 16.863281 12.191406 16.859375 C 12.003906 16.890625 11.886719 16.980469 11.769531 17.125 C 11.738281 17.164062 11.710938 17.207031 11.679688 17.25 C 11.648438 17.296875 11.617188 17.34375 11.582031 17.390625 C 11.550781 17.4375 11.519531 17.484375 11.484375 17.53125 C 11.214844 17.921875 10.921875 18.265625 10.59375 18.609375 C 10.558594 18.644531 10.523438 18.683594 10.488281 18.71875 C 10.285156 18.933594 10.066406 19.128906 9.835938 19.316406 C 9.808594 19.339844 9.78125 19.363281 9.753906 19.386719 C 9.570312 19.53125 9.464844 19.570312 9.234375 19.546875 C 9.113281 19.492188 9.113281 19.492188 8.992188 19.414062 C 8.945312 19.386719 8.902344 19.355469 8.855469 19.328125 C 8.78125 19.28125 8.78125 19.28125 8.710938 19.234375 C 8.660156 19.203125 8.613281 19.171875 8.558594 19.136719 C 7.335938 18.351562 7.335938 18.351562 7.171875 18.1875 C 7.171875 18.09375 7.167969 18 7.171875 17.90625 C 7.257812 17.863281 7.339844 17.820312 7.421875 17.78125 C 7.476562 17.753906 7.527344 17.726562 7.582031 17.703125 C 7.671875 17.65625 7.761719 17.613281 7.855469 17.570312 C 8.101562 17.457031 8.3125 17.320312 8.527344 17.15625 C 8.566406 17.128906 8.566406 17.128906 8.605469 17.097656 C 8.789062 16.957031 8.925781 16.820312 8.972656 16.589844 C 8.96875 16.382812 8.953125 16.242188 8.8125 16.078125 C 8.621094 15.941406 8.457031 15.90625 8.230469 15.941406 C 8.019531 16.015625 7.863281 16.160156 7.691406 16.296875 C 7.160156 16.699219 6.503906 16.847656 5.859375 16.96875 C 5.808594 16.976562 5.761719 16.988281 5.710938 17 C 5.421875 16.949219 5.265625 16.746094 5.0625 16.546875 C 5.003906 16.492188 4.941406 16.441406 4.882812 16.390625 C 3.597656 15.265625 3.597656 15.265625 3.546875 14.765625 C 3.53125 14.355469 3.59375 14.101562 3.863281 13.792969 C 4.183594 13.515625 4.464844 13.441406 4.878906 13.347656 C 6.324219 13.003906 7.730469 12.367188 8.824219 11.335938 C 8.855469 11.308594 8.886719 11.277344 8.921875 11.246094 C 8.949219 11.21875 8.976562 11.195312 9.003906 11.167969 C 9.140625 11.082031 9.210938 11.085938 9.375 11.109375 Z M 9.375 11.109375 M 19.742188 2.585938 C 20.148438 2.960938 20.417969 3.488281 20.453125 4.039062 C 20.457031 4.109375 20.457031 4.179688 20.457031 4.25 C 20.457031 4.28125 20.457031 4.3125 20.460938 4.34375 C 20.453125 4.820312 20.25 5.230469 20.035156 5.644531 C 20.011719 5.695312 19.984375 5.746094 19.960938 5.796875 C 19.773438 6.160156 19.585938 6.523438 19.390625 6.886719 C 19.238281 7.175781 19.089844 7.464844 18.9375 7.757812 C 18.855469 7.917969 18.769531 8.082031 18.6875 8.242188 C 18.636719 8.335938 18.589844 8.429688 18.539062 8.523438 C 18.480469 8.640625 18.417969 8.757812 18.359375 8.875 C 18.339844 8.914062 18.320312 8.949219 18.300781 8.984375 C 18.160156 9.253906 18 9.511719 17.828125 9.765625 C 17.757812 9.886719 17.757812 9.886719 17.769531 10.007812 C 17.820312 10.144531 17.878906 10.261719 17.945312 10.390625 C 18.414062 11.300781 18.359375 12.292969 18.054688 13.242188 C 18.015625 13.359375 17.976562 13.476562 17.933594 13.59375 C 17.917969 13.628906 17.90625 13.667969 17.894531 13.707031 C 17.796875 13.953125 17.796875 13.953125 17.667969 14.015625 C 17.460938 14.015625 17.320312 13.925781 17.140625 13.832031 C 17.082031 13.800781 17.082031 13.800781 17.023438 13.773438 C 16.902344 13.707031 16.78125 13.644531 16.65625 13.578125 C 16.578125 13.539062 16.5 13.496094 16.417969 13.453125 C 16.21875 13.351562 16.019531 13.246094 15.824219 13.140625 C 15.625 13.039062 15.429688 12.933594 15.230469 12.828125 C 15.195312 12.808594 15.15625 12.789062 15.121094 12.769531 C 14.835938 12.621094 14.554688 12.476562 14.273438 12.328125 C 13.949219 12.160156 13.625 11.988281 13.300781 11.820312 C 12.9375 11.628906 12.574219 11.4375 12.210938 11.25 C 12.050781 11.167969 11.890625 11.082031 11.726562 11 C 11.632812 10.949219 11.539062 10.902344 11.441406 10.851562 C 10.707031 10.472656 10.707031 10.472656 10.421875 10.300781 C 10.390625 10.28125 10.359375 10.261719 10.328125 10.246094 C 10.265625 10.171875 10.265625 10.171875 10.238281 10.042969 C 10.277344 9.824219 10.398438 9.71875 10.554688 9.5625 C 10.609375 9.507812 10.664062 9.453125 10.71875 9.394531 C 10.757812 9.355469 10.757812 9.355469 10.800781 9.3125 C 10.871094 9.242188 10.933594 9.164062 10.996094 9.085938 C 11.46875 8.527344 12.316406 8.101562 13.03125 7.96875 C 13.105469 7.96875 13.175781 7.96875 13.25 7.96875 C 13.59375 7.972656 13.59375 7.972656 13.921875 7.875 C 14.136719 7.652344 14.230469 7.347656 14.339844 7.0625 C 14.414062 6.878906 14.507812 6.707031 14.605469 6.53125 C 14.644531 6.457031 14.683594 6.382812 14.722656 6.308594 C 14.742188 6.269531 14.765625 6.230469 14.785156 6.1875 C 14.921875 5.925781 15.058594 5.660156 15.195312 5.398438 C 15.246094 5.296875 15.296875 5.195312 15.351562 5.097656 C 15.5 4.804688 15.648438 4.515625 15.796875 4.226562 C 15.839844 4.136719 15.882812 4.050781 15.925781 3.964844 C 15.980469 3.859375 16.035156 3.757812 16.085938 3.652344 C 16.464844 2.914062 16.890625 2.394531 17.691406 2.117188 C 18.402344 1.9375 19.171875 2.125 19.742188 2.585938 Z M 19.742188 2.585938 M 6.109375 7.554688 C 6.355469 7.722656 6.566406 7.917969 6.632812 8.214844 C 6.679688 8.53125 6.636719 8.765625 6.464844 9.035156 C 6.285156 9.265625 6.101562 9.355469 5.820312 9.414062 C 5.507812 9.441406 5.289062 9.375 5.046875 9.179688 C 4.820312 8.960938 4.730469 8.753906 4.714844 8.441406 C 4.722656 8.167969 4.800781 7.957031 4.988281 7.757812 C 5.308594 7.472656 5.710938 7.414062 6.109375 7.554688 Z M 6.109375 7.554688 M 3.664062 10.484375 C 3.898438 10.652344 4.035156 10.824219 4.101562 11.105469 C 4.144531 11.402344 4.09375 11.609375 3.945312 11.871094 C 3.753906 12.109375 3.585938 12.226562 3.28125 12.28125 C 2.964844 12.296875 2.734375 12.226562 2.480469 12.035156 C 2.257812 11.832031 2.191406 11.617188 2.179688 11.320312 C 2.191406 11.039062 2.265625 10.824219 2.457031 10.617188 C 2.804688 10.308594 3.257812 10.25 3.664062 10.484375 Z M 3.664062 10.484375 "/>
                                        </svg>
                                    </button>
                                </div>
                                <div class="flex items-center space-x-2">
                                    <span class="text-[10px] uppercase font-bold text-slate-500 tracking-widest whitespace-nowrap text-right">${isAdmin ? 'Owner' : 'Project'} Search:</span>
                                    <div class="bg-indigo-500/10 border border-indigo-500/30 rounded-lg px-3 py-2 text-[10px] font-bold text-indigo-400 animate-pulse uppercase tracking-tighter">${isAdmin ? 'Enabled' : 'Active'}</div>
                                </div>
                            </div>
                            <div id="tokens-list" class="space-y-4 min-h-[100px]">
                                <p class="text-slate-500 italic text-center py-10">Fetching your registered services...</p>
                            </div>
                            <div class="mt-8 flex justify-between items-center text-xs text-slate-500 border-t border-slate-800 pt-4">
                                <span id="token-pagination-info">Page 1</span>
                                <div class="flex space-x-2">
                                    <button onclick="window.tokenManager.prevPage()" class="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded disabled:opacity-50" id="token-prev-btn">Prev</button>
                                    <button onclick="window.tokenManager.nextPage()" class="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded disabled:opacity-50" id="token-next-btn">Next</button>
                                </div>
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


                        class TableManager {
                            constructor(cfg) {
                                this.endpoint = cfg.endpoint;
                                this.render = cfg.render;
                                this.renderExtra = cfg.renderExtra;
                                this.listContainer = document.getElementById(cfg.listId);
                                this.paginationInfo = document.getElementById(cfg.paginationId);
                                this.prevBtn = document.getElementById(cfg.prevBtnId);
                                this.nextBtn = document.getElementById(cfg.nextBtnId);
                                this.page = 1;
                                this.limit = 10;
                                this.searchQuery = '';
                                this.statusFilter = 'all';
                                this.timer = null;
                            }

                            async fetch(resetPage = false) {
                                if (resetPage) this.page = 1;
                                if (!this.listContainer) return;

                                const url = \`\${this.endpoint}?page=\${this.page}&limit=\${this.limit}&search=\${encodeURIComponent(this.searchQuery)}&status=\${this.statusFilter}\`;

                                try {
                                    const res = await fetch(url);
                                    const data = await res.json();
                                    
                                    const items = data.users || data.tokens || data; 
                                    const total = data.total !== undefined ? data.total : items.length;

                                    if (this.render) {
                                        let content = '';
                                        if (this.renderExtra) content += this.renderExtra(items);

                                        if (items.length === 0 && !this.renderExtra) { 
                                            // Only show generic empty state if renderExtra didn't handle it
                                            content += this.getEmptyState();
                                        } else {
                                            content += items.map(this.render).join('');
                                        }
                                        this.listContainer.innerHTML = content;
                                    }
                                    
                                    this.updatePagination(total);
                                } catch (e) {
                                    this.listContainer.innerHTML = \`<div class="text-center py-4 text-red-400">Error: \${e.message}</div>\`;
                                }
                            }

                            getEmptyState() {
                                return '<div class="text-center py-8 text-slate-500 italic">No results found</div>';
                            }

                            updatePagination(total) {
                                if (!this.paginationInfo) return;
                                const totalPages = Math.ceil(total / this.limit) || 1;
                                this.paginationInfo.innerText = \`Page \${this.page} of \${totalPages} (\${total} total)\`;
                                this.prevBtn.disabled = this.page <= 1;
                                this.nextBtn.disabled = this.page >= totalPages;
                            }
                            
                            nextPage() { this.page++; this.fetch(); }
                            prevPage() { if (this.page > 1) this.page--; this.fetch(); }
                            
                            debounceSearch(val) {
                                this.searchQuery = val;
                                // Toggle clear button visibility if it exists
                                const inputId = this.endpoint.includes('users') ? 'user-search' : 'token-search';
                                const clearBtn = document.getElementById(inputId + '-clear');
                                if (clearBtn) clearBtn.classList.toggle('hidden', !val);
                                
                                clearTimeout(this.timer);
                                this.timer = setTimeout(() => this.fetch(true), 300);
                            }

                            clearSearch() {
                                const inputId = this.endpoint.includes('users') ? 'user-search' : 'token-search';
                                const input = document.getElementById(inputId);
                                if (input) {
                                    input.value = '';
                                    this.debounceSearch('');
                                }
                            }

                            setStatus(val) {
                                this.statusFilter = val;
                                this.fetch(true);
                            }
                        }

                        // Initialize Managers
                        window.userManager = new TableManager({
                            endpoint: '/dashboard/admin/users',
                            listId: 'users-list-body',
                            paginationId: 'user-pagination-info',
                            prevBtnId: 'user-prev-btn',
                            nextBtnId: 'user-next-btn',
                            render: (u) => \`
                                <tr class="hover:bg-slate-800/30 transition-colors">
                                    <td class="px-4 py-3 font-mono text-xs text-slate-400">\${u.github_id}</td>
                                    <td class="px-4 py-3 font-bold text-indigo-300">\${u.username}</td>
                                    <td class="px-4 py-3 text-center">\${u.hook_count || 0}</td>
                                    <td class="px-4 py-3 text-center text-[10px] uppercase font-bold \${u.is_banned ? 'text-red-500' : 'text-green-500'}">\${u.is_banned ? 'BANNED' : 'ACTIVE'}</td>
                                    <td class="px-4 py-3 text-right space-x-2">
                                        <button onclick="window.toggleBan('\${u.github_id}', \${!u.is_banned})" class="text-xs uppercase font-bold tracking-wider \${u.is_banned ? 'text-green-400 hover:text-green-300' : 'text-amber-400 hover:text-amber-300'}">\${u.is_banned ? 'Unban' : 'Ban'}</button>
                                        <button onclick="window.deleteUser('\${u.github_id}', '\${u.username}')" class="text-red-400 hover:text-red-300 text-xs font-bold uppercase tracking-wider">Delete</button>
                                    </td>
                                </tr>\`
                        });

                        window.tokenManager = new TableManager({
                            endpoint: '/dashboard/tokens',
                            listId: 'tokens-list',
                            paginationId: 'token-pagination-info',
                            prevBtnId: 'token-prev-btn',
                            nextBtnId: 'token-next-btn',
                            render: (t) => {
                                const publicUrl = window.location.origin + '/h/' + t.token;
                                const projectName = t.metadata?.project_name || 'Default';
                                return \`
                                <div class="bg-slate-950 p-6 rounded-2xl border border-slate-800 bg-slate-900/40 shadow-lg group/item">
                                    <div class="flex-1">
                                        <!-- Top Row: Project Branding & Action -->
                                        <div class="flex items-center justify-between mb-3">
                                            <div class="flex items-center space-x-2 flex-1 mr-4 overflow-hidden">
                                                <span class="text-[10px] uppercase font-black text-slate-500 tracking-tighter whitespace-nowrap">\${isAdmin ? 'OWNER:' : 'PROJECT:'}</span>
                                                \${isAdmin 
                                                    ? \`<span class="text-[10px] bg-slate-800 px-2 py-0.5 rounded text-slate-400 font-bold">\${t.owner_name}</span>\`
                                                    : \`<span class="text-sm font-bold text-indigo-300 hover:text-indigo-200 cursor-pointer flex items-center group/proj overflow-hidden" onclick="window.renameProject(this, '\${t.token}', '\${projectName}')">
                                                       <span class="truncate">\${projectName}</span>
                                                       <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3 ml-2 flex-shrink-0 opacity-0 group-hover/proj:opacity-100 transition-opacity text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" /></svg>
                                                     </span>\`
                                                }
                                            </div>
                                            <button onclick="window.deleteToken('\${t.token}')" class="text-red-500 text-[10px] font-black hover:bg-red-500/10 hover:border-red-500/20 border border-transparent px-3 py-1.5 rounded-lg transition-all uppercase tracking-widest flex-shrink-0">Delete</button>
                                        </div>

                                        <!-- Middle Row: Public URL -->
                                        <div class="mb-4">
                                            <div onclick="window.copySnippet(this)" class="bg-black/60 border border-slate-700/50 rounded-lg p-3 text-xs text-indigo-300 font-mono cursor-pointer hover:border-indigo-500/30 transition-all select-all">\${publicUrl}</div>
                                        </div>

                                        <!-- Bottom Row: Technical Metadata -->
                                        <div class="flex flex-col md:flex-row md:items-center justify-between gap-y-2 md:gap-y-0 text-[10px]">
                                            <div class="flex items-center space-x-2">
                                                <span class="uppercase font-black text-slate-600 tracking-tighter">TUNNEL ID:</span>
                                                <code class="text-slate-500 font-mono italic">\${t.token}</code>
                                            </div>
                                            <div class="flex items-center space-x-2">
                                                <span class="uppercase font-black text-slate-600 tracking-tighter">SERVICE:</span>
                                                <p class="text-slate-500 italic font-mono">\${t.metadata?.onion_service_id || 'unknown'}.onion</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>\`;
                            },
                             renderExtra: function(items) {
                                if (isAdmin) return '';
                                const apiKey = document.getElementById('api-key-text')?.dataset.key || '<your-api-key>';
                                const hasItems = items && items.length > 0;
                                const relayUrl = window.location.origin;
                                return \`
                                        <div id="quick-setup-container" class="\${hasItems ? 'mb-8' : 'mb-12 text-left'}">
                                            <details \${!hasItems ? 'open' : ''} class="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl group">
                                                <summary class="bg-indigo-500/10 px-6 py-4 border-b border-slate-800 flex justify-between items-center cursor-pointer hover:bg-indigo-500/20 transition-colors list-none">
                                                    <div class="flex items-center space-x-3">
                                                        <h3 class="text-sm font-bold text-indigo-300 uppercase tracking-widest">Quick Setup Guide</h3>
                                                        \${!hasItems ? '<span class="px-2 py-0.5 bg-indigo-500 text-[10px] font-bold rounded animate-pulse">RECOMMENDED</span>' : ''}
                                                    </div>
                                                    <div class="flex items-center space-x-4">
                                                        <div class="flex items-center space-x-2 bg-black/40 px-3 py-1 rounded border border-slate-800">
                                                            <code class="text-[10px] text-indigo-400 font-mono italic">\${relayUrl}</code>
                                                        </div>
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-slate-500 group-open:rotate-180 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
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
                                                                    docker run -d --name onion-pipe -v ./registration:/registration -v ./onion_id:/var/lib/tor/hidden_service -e API_TOKEN="<span class="text-white font-bold">\${apiKey}</span>" -e RELAY_URL="\${relayUrl}" -e FORWARD_DEST="http://host.docker.internal:8080" <span class="text-indigo-400 font-bold">sapphive/onion-pipe</span>
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
                                                                    <div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="text-indigo-400">RELAY_URL:</span> "\${relayUrl}"</div>
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
                                                                docker exec onion-pipe <span class="text-indigo-400 font-bold">register</span>
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
                                        </div>\`;
                            }
                        });

                        window.refreshUsers = () => window.userManager.fetch();
                        window.refreshTokens = () => window.tokenManager.fetch();

                        window.toggleBan = async function(id, ban) {
                            if (!await window.confirmModal('Update Status', \`Are you sure you want to \${ban ? 'BAN' : 'UNBAN'} this user?\`)) return;
                            await fetch(\`/dashboard/admin/users/\${id}/status\`, { 
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({ status: ban ? 'banned' : 'active' })
                            });
                             window.userManager.fetch();
                        };

                        window.deleteUser = async function(id, username) {
                            if (!await window.confirmModal('Delete User', \`Are you sure you want to delete user \${username}? This will remove all their tokens and keys.\`)) return;
                            try {
                                const res = await fetch(\`/dashboard/admin/users/\${id}\`, { method: 'DELETE' });
                                if (res.ok) {
                                    window.showToast(\`User \${username} deleted\`, 'red');
                                    window.userManager.fetch();
                                }
                            } catch (e) { window.showToast(e.message, 'red'); }
                        };

                        window.deleteToken = async function(token) {
                            if (!await window.confirmModal('Delete Hook', 'Permanently remove this mapping?')) return;
                            await fetch('/dashboard/tokens/' + token, { method: 'DELETE' });
                            window.tokenManager.fetch();
                            window.showToast('Hook Removed', 'red');
                        };

                        window.renameProject = async function(el, token, current) {
                            if (el.querySelector('input')) return; // already editing
                            const originalHTML = el.innerHTML;
                            let isSaving = false;
                            
                            const input = document.createElement('input');
                            input.type = 'text';
                            input.value = current;
                            input.maxLength = 50;
                            input.className = 'bg-slate-950 border border-indigo-500/50 rounded px-2 py-0.5 text-sm text-indigo-300 outline-none w-full font-bold focus:ring-1 focus:ring-indigo-500';
                            
                            el.innerHTML = '';
                            el.classList.add('flex-1'); // Take full width of parent's flex-1 mr-4
                            el.appendChild(input);
                            input.focus();
                            input.select();

                            const cleanup = () => { 
                                el.classList.remove('flex-1');
                                if (!isSaving) el.innerHTML = originalHTML; 
                            };
                            
                            const save = async () => {
                                if (isSaving) return;
                                const newName = input.value.trim();
                                if (!newName || newName === current) return cleanup();
                                
                                isSaving = true;
                                try {
                                    const res = await fetch(\`/dashboard/tokens/\${token}/project\`, {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ projectName: newName })
                                    });
                                    if (res.ok) {
                                        window.showToast('Project Renamed');
                                        window.tokenManager.fetch();
                                    } else {
                                        const err = await res.json();
                                        window.showToast(err.error || 'Update failed', 'red');
                                        isSaving = false;
                                        cleanup();
                                    }
                                } catch (e) {
                                    window.showToast(e.message, 'red');
                                    isSaving = false;
                                    cleanup();
                                }
                            };

                            input.onblur = save;
                            input.onkeydown = (e) => {
                                if (e.key === 'Enter') { e.preventDefault(); input.onblur = null; save(); }
                                if (e.key === 'Escape') { e.preventDefault(); input.onblur = null; cleanup(); }
                            };
                        };

                        window.toggleApiKey = function() {
                            const el = document.getElementById('api-key-text');
                            el.style.webkitTextSecurity = el.style.webkitTextSecurity === 'disc' ? 'none' : 'disc';
                        };

                        window.showToast = function(message, type = 'indigo') {
                            const toast = document.createElement('div');
                            const icon = type === 'red' ? 'fa-exclamation-circle' : 'fa-check-circle';
                            toast.className = 'fixed bottom-8 left-1/2 -translate-x-1/2 px-6 py-3 rounded-full bg-slate-900 border border-' + type + '-500/50 shadow-2xl text-' + type + '-400 text-xs font-bold uppercase tracking-widest z-[100] animate-bounce';
                            toast.innerHTML = '<i class="fas ' + icon + ' mr-2"></i> ' + message;
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
                        if (isAdmin) {
                            window.refreshNodes();
                            window.refreshUsers();
                        }
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
    
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const search = (req.query.search as string) || '';

    try {
        if (isAdmin) {
          const result = await redis.getPaginatedTokens(null, page, limit, search);
          return res.json(result);
        } else {
          const result = await redis.getPaginatedTokens(user.id, page, limit, search);
          return res.json(result);
        }
    } catch (e) {
        res.status(500).json({ error: "Failed to fetch tokens" });
    }
  });

  app.post("/dashboard/api-key/rotate", requireAuth, async (req, res) => {
    const isAdmin = req.user?.isAdmin;
    if (isAdmin) return res.status(400).json({ error: "Admin has no API key" });

    const user = req.user as PassportUser;
    const newKey = await redis.rotateUserApiKey(user.id);
    res.json({ api_key: newKey });
  });

  app.post("/dashboard/tokens/:token/project", requireAuth, async (req, res) => {
    const { token } = req.params;
    const { projectName } = req.body;
    const user = req.user as PassportUser;

    if (!projectName || projectName.length > 50) {
      return res.status(400).json({ error: "Invalid project name" });
    }

    try {
      await redis.updateTokenProject(token as string, user.id, projectName as string);
      res.json({ success: true });
    } catch (e: any) {
      res.status(403).json({ error: e.message });
    }
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
  let {
    onion_service_id,
    public_key,
    registration_secret,
    github_id,
    token: apiKey,
  } = req.body;

  // Clean inputs
  if (onion_service_id) onion_service_id = onion_service_id.trim();
  if (public_key) public_key = public_key.trim();
  if (apiKey) apiKey = apiKey.trim();

  if (!onion_service_id) {
    return res.status(400).json({ error: "MISSING_ONION_ID: Registration failed because no Onion address was provided." });
  }

  if (!public_key) {
    return res
      .status(400)
      .json({
        error:
          "MISSING_PUBLIC_KEY: End-to-End Encryption is mandatory. Initialize your keys first.",
      });
  }

  let targetUserId: string | null = null;

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

  let finalUserId = targetUserId || (req.user as any)?.id || github_id;
  let token = uuidv4();

  // 3. Collision Check / Update Logic
  // If this onion_service_id is already registered, we update it instead of creating a new one
  const allExisting = await redis.getAllTokens();
  const existing = allExisting.find(t => t.metadata.onion_service_id === onion_service_id);

  if (existing) {
    // If it belongs to someone else, reject it (Security)
    if (existing.metadata.github_id && finalUserId && existing.metadata.github_id !== finalUserId) {
      return res.status(409).json({ 
          error: "ONION_ID_CLAIMED: This Onion address is already registered by another user. If you own it, please contact the relay administrator." 
      });
    }
    // Update existing token
    token = existing.token;
    logger.info({ token, onion_service_id, userId: finalUserId }, "Updating existing hook registration (Public Key Rotation)");
  }

  const metadata: TokenMetadata = {
    onion_service_id,
    public_key,
    status: "active",
    created_at: Math.floor(Date.now() / 1000).toString(),
    github_id: finalUserId || undefined
  };

  await redis.setTokenMetadata(token, metadata);

  logger.info(
    { token, onion_service_id, userId: metadata.github_id, isUpdate: !!existing },
    existing ? "Client registration updated" : "New client registered",
  );
  res.json({
    token,
    relay_url: process.env.PUBLIC_RELAY_URL || `http://localhost:${PORT}`,
  });
});

app.post("/h/:token", express.text({ type: "*/*" }), async (req, res) => {
  const token = req.params.token as string;
  try {
    const metadata = await redis.getTokenMetadata(token);
    if (!metadata || metadata.status !== "active") return res.status(404).end();

    // 1. BAN CHECK: Ensure the owner isn't banned
    if (metadata.github_id) {
        const isBanned = await redis.isUserBanned(metadata.github_id);
        if (isBanned) return res.status(403).json({ error: "TUNNEL_SUSPENDED" });
    }

    // 2. RATE LIMITING: Simple 100 req / 10s per token
    const rateKey = `ratelimit:${token}`;
    const count = await redis.getClient().incr(rateKey);
    if (count === 1) await redis.getClient().expire(rateKey, 10);
    if (count > 100) return res.status(429).json({ error: "TOO_MANY_REQUESTS" });

    if (!metadata.public_key) {
      logger.error({ token }, "Terminal Error: Active hook missing public key");
      return res.status(500).json({
        error: "SECURITY_VIOLATION",
      });
    }

    // Try to parse as JSON if possible for a cleaner payload, otherwise send as raw string
    let data = req.body;
    try {
      if (typeof req.body === 'string' && req.body.startsWith('{')) {
          data = JSON.parse(req.body);
      }
    } catch (e) {
      // Keep as string
    }

    const payloadToSend = await CryptoService.encrypt(
      JSON.stringify({
        data,
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
      return res.status(503).json({ error: "NO_BRIDGES_AVAILABLE" });

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
      .json({ error: "RELAY_INTERNAL_ERROR" });
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
