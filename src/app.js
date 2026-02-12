const express = require('express');
const app = express();
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const SamlStrategy = require('@node-saml/passport-saml').Strategy;
const fs = require('fs');
const PORT = process.env.PORT || 3000;

// EJS View Engine Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Middleware
app.use(express.static(path.join(__dirname, '../public')));
app.use(express.urlencoded({ extended: true })); // For parsing form data
app.use(express.json());

// DEBUG: Log all requests to see what the IdP is sending
app.use((req, res, next) => {
    console.log(`[REQUEST] ${req.method} ${req.url}`);
    next();
});

// Session Configuration (Required for Passport)
app.use(session({
    secret: 'bu_gizli_anahtar_degistirilmeli', // Change this in production
    resave: true, // Force save even if not modified (legacy/compatibility)
    saveUninitialized: true, // Save new but not modified sessions
    cookie: {
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// --- Authentication Logic Start ---

// Mock Database (Just for demonstration)
const users = [
    { id: 1, username: 'admin', password: 'password123', email: 'admin@example.com' }
];

// --- Configuration Logic ---
const configPath = path.join(__dirname, '../saml-config.json');

// Helper to load configuration
function loadSamlConfig() {
    try {
        if (fs.existsSync(configPath)) {
            const data = fs.readFileSync(configPath, 'utf8');
            return JSON.parse(data);
        }
    } catch (e) {
        console.error('Error loading SAML config:', e);
    }
    // Default fallback
    return {
        strict: true,
        debug: false,
        sp: {
            entityId: 'passport-saml',
            acsUrl: 'http://localhost:3000/login/sso/callback',
            nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        },
        idp: {
            entityId: 'https://dev-xxxxxxxxx.us.auth0.com/samlp/xxxxxxxxx',
            ssoUrl: 'https://dev-xxxxxxxxx.us.auth0.com/samlp/xxxxxxxxx',
            x509cert: 'MIIDpDCCAoygAwIBAgIG...'
        },
        security: {
            authnRequestsSigned: false,
            wantAssertionsSigned: true,
            signatureAlgorithm: 'sha256'
        },
        attributeMapping: {
            email: 'email',
            username: 'uid'
        }
    };
}

// Config Mapper: Convert our nested config to passport-saml options
function mapConfigToStrategyOptions(config) {
    const rawPrivateKey = config.sp.privateKey && config.sp.privateKey.trim().length > 0 ? config.sp.privateKey.trim() : null;

    const result = {
        // SP Settings
        callbackUrl: config.sp.acsUrl,
        issuer: config.sp.entityId,
        identifierFormat: config.sp.nameIdFormat,
        decryptionPvk: rawPrivateKey,
        privateKey: rawPrivateKey, // for signing checks

        // IdP Settings
        entryPoint: config.idp.ssoUrl,
        cert: config.idp.x509cert,
        logoutUrl: config.idp.sloUrl,

        // Security Settings (partial mapping for node-saml)
        authnRequestBinding: 'HTTP-Redirect', // Default
        wantAssertionsSigned: config.security.wantAssertionsSigned,
        // Safety check: Explicit false if no key
        authnRequestsSigned: rawPrivateKey ? config.security.authnRequestsSigned : false,
        signatureAlgorithm: config.security.signatureAlgorithm,
        digestAlgorithm: config.security.digestAlgorithm,
        acceptedClockSkewMs: (config.security.clockSkew || 300) * 1000, // seconds to ms
        disableRequestedAuthnContext: !config.security.requestedAuthnContext

        // ... extend as needed based on passport-saml documentation
    };

    // DEBUG: Inspect the result of mapping
    console.log('[DEBUG] Strategy Options Mapped:', {
        authnRequestsSigned: result.authnRequestsSigned,
        hasPrivateKey: !!result.privateKey,
        securityConfig: config.security
    });

    return result;
}

// Helper to save configuration
function saveSamlConfig(config) {
    try {
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
        return true;
    } catch (e) {
        console.error('Error saving SAML config:', e);
        return false;
    }
}

// Initial configuration load
let samlConfig = loadSamlConfig();

// --- SAML Event Log System (Educational) ---
// --- SAML Event Log System (Persistent) ---
const eventsLogPath = path.join(__dirname, '../saml-events.json');

// Helper to load events from file
function loadSamlEvents() {
    try {
        if (fs.existsSync(eventsLogPath)) {
            const data = fs.readFileSync(eventsLogPath, 'utf8');
            return JSON.parse(data);
        }
    } catch (e) {
        console.error('Error loading SAML events:', e);
    }
    return [];
}

// Helper to save events to file
function saveSamlEvents(events) {
    try {
        fs.writeFileSync(eventsLogPath, JSON.stringify(events, null, 2), 'utf8');
    } catch (e) {
        console.error('Error saving SAML events:', e);
    }
}

// Initial load into global for quick access (optional, but good for read perf)
global.samlEvents = loadSamlEvents();

function addSamlEvent(stage, title, message, data = null) {
    const event = {
        id: Date.now() + Math.random(), // Unique ID
        timestamp: new Date(),
        stage: stage, // 'SP', 'IdP', 'System'
        title: title,
        message: message,
        data: data
    };

    // Load current state (in case of multiple processes, though node is single thread here)
    let currentEvents = loadSamlEvents();

    // Prepend new event (Newest First)
    currentEvents.unshift(event);

    // Keep logs manageable (Limit to last 200 events)
    if (currentEvents.length > 200) {
        currentEvents = currentEvents.slice(0, 200);
    }

    // Save back to file
    saveSamlEvents(currentEvents);

    // Update memory
    global.samlEvents = currentEvents;
}
// -------------------------------------------

// 1. Local Strategy Configuration
passport.use(new LocalStrategy(
    (username, password, done) => {
        const user = users.find(u => u.username === username);

        if (!user) {
            return done(null, false, { message: 'Kullanıcı bulunamadı.' });
        }

        if (user.password !== password) {
            return done(null, false, { message: 'Hatalı şifre.' });
        }

        return done(null, user);
    }
));

// Serialize user into the session
passport.serializeUser((user, done) => {
    done(null, user); // Storing the whole user object for simplicity with SAML
});

// Deserialize user from the session
passport.deserializeUser((user, done) => {
    // In a real app, you might fetch from DB using user.id
    done(null, user);
});

// 2. SAML Strategy Configuration
// Initial setup using the default/in-memory config variables
// This will be overwritten when admin updates settings
// 2. SAML Strategy Configuration
// Will be initialized using configuration from file (loaded below)
// We need to define a default strategy initially to prevent passport errors on startup if config is missing or invalid, 
// but the main logic is handled by the dynamic re-configuration.

// 2. SAML Strategy Configuration
// Initialize using configuration from file
const strategyOptions = mapConfigToStrategyOptions(samlConfig);

// Fix: explicit idpCert mapping if needed (MUST be done before usage)
strategyOptions.idpCert = strategyOptions.cert;

// Debugging: check values (Moved after fix so idpCert is correct)
console.log('SAML Strategy Options (Final):', {
    entryPoint: strategyOptions.entryPoint,
    issuer: strategyOptions.issuer,
    cert: strategyOptions.cert ? 'EXISTS' : 'MISSING',
    idpCert: strategyOptions.idpCert ? 'EXISTS' : 'MISSING', // Should be populated now
    authnRequestsSigned: strategyOptions.authnRequestsSigned
});

passport.use('saml', new SamlStrategy(
    strategyOptions,
    (profile, done) => {
        // Log Profile received
        addSamlEvent('SP', 'Identity Verified', 'IdP kimlik doğrulamasını başarıyla tamamladı.', { profileKeys: Object.keys(profile) });

        // Dynamic Attribute Mapping
        addSamlEvent('SP', 'Attribute Mapping', 'Kullanıcı özellikleri yerel modele eşleniyor.');
        const emailKey = samlConfig.attributeMapping ? samlConfig.attributeMapping.email : 'email';
        const usernameKey = samlConfig.attributeMapping ? samlConfig.attributeMapping.username : 'uid';

        // Helper to find attribute case-insensitively or by exact key
        const getAttribute = (obj, key) => {
            if (!obj) return null;
            // 1. Exact match
            if (obj[key]) return obj[key];
            // 2. Case-insensitive match (if simplified profile)
            const lowerKey = key.toLowerCase();
            const foundKey = Object.keys(obj).find(k => k.toLowerCase() === lowerKey);
            if (foundKey) return obj[foundKey];
            return null;
        };

        // Try to find email in profile root or attributes
        let email = getAttribute(profile, emailKey) ||
            (profile.attributes && getAttribute(profile.attributes, emailKey));

        // Fallback to standard claims/hardcoded if not found via mapping
        if (!email) {
            email = profile.email || profile.Email || 'saml@example.com';
        }

        // Try to find username
        let username = getAttribute(profile, usernameKey) ||
            (profile.attributes && getAttribute(profile.attributes, usernameKey)) ||
            profile.nameID ||
            profile.NameID ||
            email ||
            'SAML User';

        const user = {
            id: profile.nameID || email || 'saml-user',
            username: username,
            email: email,
            source: 'saml',
            samlProfile: profile
        };
        return done(null, user);
    }
));

// --- Authentication Logic End ---

// Routes

// Home Route
app.get('/', (req, res) => {
    res.render('index', {
        title: 'Ana Sayfa',
        message: 'Hoş geldiniz! SAML ve Local Auth sistemi.',
        user: req.user
    });
});

// Glossary Page
app.get('/glossary', (req, res) => {
    res.render('glossary');
});

// Login Page
app.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/dashboard');
    }
    // For educational purposes, sending default credentials to the view
    const defaultUser = users[0];
    res.render('login', {
        title: 'Giriş Yap',
        defaultUser: defaultUser
    });
});

// Login Process (Local)
app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureMessage: true
}));

// Login Process (SAML Trigger)
// ----------------------------------------------------------------------------------
// REQUIRED CONFIGURATION:
//   ACS URL / Callback URL (Identity Provider Setting):
//     {{BASE_URL}}/login/sso/callback
//
//     Example: http://localhost:3000/login/sso/callback
//     Example: https://your-domain.com/login/sso/callback
// ----------------------------------------------------------------------------------

// POST Handler: Catch incorrect IdP POSTs to /login/sso
app.post('/login/sso', (req, res) => {
    // If IdP sends SAMLResponse here (HTTP-POST Binding), it's a wrong configuration
    if (req.body && req.body.SAMLResponse) {
        // Helpful info for debugging
        const correctUrl = `${req.protocol}://${req.get('host')}/login/sso/callback`;

        console.error('--------------------------------------------------');
        console.error('[CRITICAL CONFIG ERROR] IdP sent response to /login/sso!');
        console.error(`Expected (Correct) ACS URL: ${correctUrl}`);
        console.error('--------------------------------------------------');

        return res.status(400).send(`
            <div style="font-family: sans-serif; padding: 20px; text-align: center;">
                <h1 style="color: #e74c3c;">⚠️ Configuration Error Detected</h1>
                <p>The Identity Provider (IdP) is sending the SAML Response to the wrong URL.</p>
                
                <div style="background: #e8f5e9; padding: 15px; border: 2px solid #4caf50; border-radius: 5px; margin: 20px auto; max-width: 600px;">
                    <h3 style="color: #2e7d32; margin-top: 0;">✅ CORRECT SETTING (Update your IdP):</h3>
                    <p style="font-size: 1.2em; font-weight: bold;">ACS URL / Callback URL:</p>
                    <code style="background: #fff; padding: 10px; display: block; border: 1px solid #ccc;">${correctUrl}</code>
                </div>

                <div style="background: #ffebee; padding: 10px; border-radius: 5px; margin: 20px auto; max-width: 600px; text-align: left;">
                    <p><strong>Diagnosis:</strong> Your IdP is currently sending data to <code>.../login/sso</code> instead of <code>.../login/sso/callback</code>.</p>
                </div>
            </div>
        `);
    }
    // Default 404 behavior for other POSTs
    res.status(404).send('Cannot POST /login/sso. This endpoint only supports GET to initiate login.');
});

// GET Handler: Initiate Login
app.get('/login/sso', (req, res, next) => {
    // LOOP DETECTION: Check if IdP is redirecting back here with a response
    // Safely check properties to avoid 'undefined' errors
    const hasSAMLResponse = (req.query && req.query.SAMLResponse) || (req.body && req.body.SAMLResponse);
    if (hasSAMLResponse) {
        console.error('[CRITICAL] SAMLResponse detected at /login/sso! This indicates an IdP configuration error.');
        console.error('The IdP ACS URL is likely set to /login/sso instead of /login/sso/callback');
        return res.status(400).send(`
            <h1>Configuration Error Detected</h1>
            <p>The Identity Provider (IdP) sent the SAML Response to <code>/login/sso</code>.</p>
            <p>This page is for <b>starting</b> login, not receiving the result.</p>
            <p><b>Solution:</b> Change your IdP's ACS (Assertion Consumer Service) URL to:</p>
            <pre>${req.protocol}://${req.get('host')}/login/sso/callback</pre>
        `);
    }

    // Start fresh log for new flow? 
    // No, for persistent log we want to keep history.
    // But we might want to mark the start of a flow clearly.
    addSamlEvent('SP', 'Flow Started', 'Kullanıcı SSO giriş işlemini başlattı (Discovery).');

    // Intercept redirect to capture SAMLRequest
    const originalRedirect = res.redirect;
    res.redirect = function (url) {
        try {
            const urlObj = new URL(url);
            const samlRequest = urlObj.searchParams.get('SAMLRequest');
            if (samlRequest) {
                try {
                    const zlib = require('zlib');
                    const buffer = Buffer.from(samlRequest, 'base64');
                    // Use synchronous inflation 
                    const result = zlib.inflateRawSync(buffer);
                    const xml = result.toString();
                    req.session.samlRequestXML = xml;

                    // Explicitly save session to ensure persistence before redirect
                    // Also save to global for fallback
                    global.recentSamlRequestXML = xml;

                    addSamlEvent('SP', 'SAML Request Generated', 'AuthnRequest oluşturuldu ve imzalandı (eğer aktifse).', { xmlSnippet: xml.substring(0, 200) + '...' });
                    addSamlEvent('System', 'Redirecting', 'Kullanıcı Identity Provider\'a yönlendiriliyor...');

                    return req.session.save((err) => {
                        if (err) console.error('Session save error:', err);
                        return originalRedirect.apply(this, arguments);
                    });

                } catch (err) {
                    console.error('Error inflating SAMLRequest:', err);
                }
            }
        } catch (e) {
            console.error('Error capturing SAMLRequest:', e);
        }
        return originalRedirect.apply(this, arguments);
    };
    next();
}, passport.authenticate('saml', {
    failureRedirect: '/login',
    failureFlash: true
}), (req, res) => {
    res.redirect('/');
});

// Login Process (SAML Callback)
app.post('/login/sso/callback',
    (req, res, next) => {
        addSamlEvent('SP', 'SAML Response Received', 'IdP\'den yanıt döndü (Assertion Consumer Service).');

        // Capture raw SAMLResponse
        if (req.body.SAMLResponse) {
            try {
                const buffer = Buffer.from(req.body.SAMLResponse, 'base64');
                req.session.samlResponseXML = buffer.toString('utf-8');
                // Express-session auto-saves at end of request.
                global.recentSamlResponseXML = req.session.samlResponseXML; // Fallback

                addSamlEvent('SP', 'XML Decoded', 'SAML Response XML formatına çözüldü.');

                // --- IdP Status Analysis ---
                const xml = req.session.samlResponseXML;

                // Extract StatusCode
                // Look for <samlp:StatusCode Value="..."> or <StatusCode Value="...">
                const statusCodeMatch = xml.match(/StatusCode\s+Value=["']([^"']+)["']/);
                if (statusCodeMatch && statusCodeMatch[1]) {
                    const fullStatus = statusCodeMatch[1];
                    const statusShort = fullStatus.split(':').pop(); // e.g. 'Success' from '...:status:Success'
                    addSamlEvent('IdP', 'Login Status', `IdP Kararı: ${statusShort}`, { fullStatus: fullStatus });
                }

                // Extract StatusMessage (Optional)
                const statusMsgMatch = xml.match(/StatusMessage>([^<]+)</);
                if (statusMsgMatch && statusMsgMatch[1]) {
                    addSamlEvent('IdP', 'Status Message', `IdP Mesajı: ${statusMsgMatch[1]}`);
                }
                // ---------------------------

            } catch (e) {
                console.error('Error capturing SAMLResponse:', e);
                addSamlEvent('System', 'Error', 'SAML Response işlenirken hata oluştu.', { error: e.message });
            }
        }

        // Debugging: Check if request XML exists in session before authentication
        if (req.session.samlRequestXML) {
            // Store in locals to survive potential session regeneration during passport.authenticate
            res.locals.tempSamlRequestXML = req.session.samlRequestXML;
        }

        next();
    },
    passport.authenticate('saml', {
        failureRedirect: '/login',
        failureFlash: true
    }),
    (req, res) => {
        // Attach the captured XMLs to the user object for display if needed
        // Or just rely on session. Ideally, we move them to user object so they persist 
        // cleanly with the user session if desired, or just keep in session.
        // For the dashboard to show them, let's ensure they are available.
        // Attach the captured XMLs to the user object for display if needed
        if (req.user) {
            // Restore from locals if session was regenerated/cleared
            if (res.locals.tempSamlRequestXML) {
                req.user.samlRequestXML = res.locals.tempSamlRequestXML;
                req.session.samlRequestXML = res.locals.tempSamlRequestXML;
            } else if (req.session.samlRequestXML) {
                req.user.samlRequestXML = req.session.samlRequestXML;
            } else if (global.recentSamlRequestXML) {
                // Fallback to global
                req.user.samlRequestXML = global.recentSamlRequestXML;
                req.session.samlRequestXML = global.recentSamlRequestXML;
            }

            if (req.session.samlResponseXML) {
                req.user.samlResponseXML = req.session.samlResponseXML;
            }
        }
        res.redirect('/dashboard');
    }
);

// Initial configuration load
// Config is already loaded at the top.

// Admin Page Route
app.get('/admin', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    // Simple authorization check (In production, check for admin role)
    if (req.user.username !== 'admin') {
        return res.status(403).send('Erişim reddedildi. Sadece adminler görebilir.');
    }

    res.render('admin', {
        title: 'SAML Yönetim Paneli',
        config: samlConfig,
        user: req.user,
        message: req.query.success ? 'Ayarlar başarıyla kaydedildi!' : null,
        events: global.samlEvents || []
    });
});

// API Endpoint for Live Events (Accessible to all authenticated users)
app.get('/api/events', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(403).json({ error: 'Erişim reddedildi' });
    }
    res.json(global.samlEvents || []);
});

// Save Configuration Route - Advanced
app.post('/admin/save-saml', (req, res) => {
    if (!req.isAuthenticated() || req.user.username !== 'admin') {
        return res.status(403).send('Erişim reddedildi.');
    }

    try {
        // We expect a structured form, or we can parse flat body to structure
        // But simpler is to reconstruct the object from the form fields.

        // 1. SP Settings - Edit Enabled
        safeSet(samlConfig, 'sp.entityId', req.body.sp_entityId);
        safeSet(samlConfig, 'sp.acsUrl', req.body.sp_acsUrl);
        safeSet(samlConfig, 'sp.nameIdFormat', req.body.sp_nameIdFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');

        if (req.body.sp_privateKey) safeSet(samlConfig, 'sp.privateKey', req.body.sp_privateKey);
        // Note: certificates usually need formatting, for demo we take raw string

        // 2. IdP Settings
        safeSet(samlConfig, 'idp.ssoUrl', req.body.idp_ssoUrl);
        safeSet(samlConfig, 'idp.entityId', req.body.idp_entityId);
        safeSet(samlConfig, 'idp.x509cert', req.body.idp_x509cert);

        // 3. Security Settings
        // Booleans come as 'on' or undefined from checkboxes
        samlConfig.security = samlConfig.security || {};
        samlConfig.security.authnRequestsSigned = req.body.sec_authnRequestsSigned === 'on';
        samlConfig.security.wantAssertionsSigned = req.body.sec_wantAssertionsSigned === 'on';
        samlConfig.security.signatureAlgorithm = req.body.sec_signatureAlgorithm || 'sha256';

        // 4. Attribute Mapping
        samlConfig.attributeMapping = {
            email: req.body.attr_email || 'email',
            username: req.body.attr_username || 'uid'
        };

        // Persist
        if (!saveSamlConfig(samlConfig)) {
            return res.status(500).send('Ayarlar kaydedilirken bir hata oluştu.');
        }

        // Re-Config Strategy
        passport.unuse('saml');
        const newOptions = mapConfigToStrategyOptions(samlConfig);

        // Fix: explicit idpCert mapping for node-saml validation
        newOptions.idpCert = newOptions.cert;

        // We must re-create the strategy with the verify callback
        passport.use('saml', new SamlStrategy(newOptions, (profile, done) => {
            // ... (Same callback logic - ideally extracted to a named function to avoid duplication)
            // Log Profile received
            addSamlEvent('SP', 'Identity Verified', 'IdP kimlik doğrulamasını başarıyla tamamladı.', { profileKeys: Object.keys(profile) });

            // Dynamic Attribute Mapping
            addSamlEvent('SP', 'Attribute Mapping', 'Kullanıcı özellikleri yerel modele eşleniyor.');
            const emailKey = samlConfig.attributeMapping ? samlConfig.attributeMapping.email : 'email';
            const usernameKey = samlConfig.attributeMapping ? samlConfig.attributeMapping.username : 'uid';

            // Helper to find attribute case-insensitively or by exact key
            const getAttribute = (obj, key) => {
                if (!obj) return null;
                // 1. Exact match
                if (obj[key]) return obj[key];
                // 2. Case-insensitive match (if simplified profile)
                const lowerKey = key.toLowerCase();
                const foundKey = Object.keys(obj).find(k => k.toLowerCase() === lowerKey);
                if (foundKey) return obj[foundKey];
                return null;
            };

            // Try to find email in profile root or attributes
            let email = getAttribute(profile, emailKey) ||
                (profile.attributes && getAttribute(profile.attributes, emailKey));

            // Fallback to standard claims/hardcoded if not found via mapping
            if (!email) {
                email = profile.email || profile.Email || 'saml@example.com';
            }

            // Try to find username
            let username = getAttribute(profile, usernameKey) ||
                (profile.attributes && getAttribute(profile.attributes, usernameKey)) ||
                profile.nameID ||
                profile.NameID ||
                email ||
                'SAML User';

            const user = {
                id: profile.nameID || email || 'saml-user',
                username: username,
                email: email,
                source: 'saml',
                samlProfile: profile
            };
            return done(null, user);
        }));

        res.redirect('/admin?success=true');

    } catch (e) {
        console.error("Config save error:", e);
        // Keep the user on the page but show error
        // Ideally we should flash this, but simple text for now
        res.status(500).send(`
            <html>
                <body style="font-family: sans-serif; padding: 2rem;">
                    <h2 style="color: red;">Ayarlar Kaydedilirken Hata Oluştu!</h2>
                    <p>${e.message}</p>
                    <pre style="background: #f0f0f0; padding: 1rem;">${e.stack}</pre>
                    <button onclick="window.history.back()">Geri Dön</button>
                </body>
            </html>
        `);
    }
});

// Helper for deep setting
function safeSet(obj, path, value) {
    if (!obj) return;
    const keys = path.split('.');
    let current = obj;
    for (let i = 0; i < keys.length - 1; i++) {
        if (!current[keys[i]]) current[keys[i]] = {};
        current = current[keys[i]];
    }
    current[keys[keys.length - 1]] = value;
}

// Dashboard (Protected Route)
app.get('/dashboard', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }

    // Attach Captured SAML XMLs from Session to User Object
    if (req.session.samlRequestXML) {
        req.user.samlRequestXML = req.session.samlRequestXML;
    } else if (global.recentSamlRequestXML) {
        // Fallback to global variable if session lost it
        req.user.samlRequestXML = global.recentSamlRequestXML;
    }
    if (req.session.samlResponseXML) {
        req.user.samlResponseXML = req.session.samlResponseXML;
    } else if (global.recentSamlResponseXML) {
        // Fallback to global variable
        req.user.samlResponseXML = global.recentSamlResponseXML;
    }

    res.render('dashboard', {
        title: 'Dashboard',
        user: req.user,
        events: global.samlEvents || []
    });
});

// Logout
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

// Start the server
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
    });
}

module.exports = app;
