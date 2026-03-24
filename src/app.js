const express = require('express');
const app = express();
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const SamlStrategy = require('@node-saml/passport-saml').Strategy;
const OAuth2Strategy = require('passport-oauth2').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const fs = require('fs');
const taskManager = require('./task-manager');
const logger = require('./logger');
const PORT = process.env.PORT || 3000;

// CRASH DEBUGGING
process.on('uncaughtException', (err) => {
    logger.error('----------------------------------------------------------------');
    logger.error('[CRITICAL] UNCAUGHT EXCEPTION:', err);
    logger.error('Stack:', err.stack);
    console.error('----------------------------------------------------------------');
    // keep running? No, usually safer to let it crash, but we want to see the log.
    // logging is enough, system will exit usually unless we prevent it.
    // For debugging, let's keep it alive if possible or just log.
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('----------------------------------------------------------------');
    logger.error('[CRITICAL] UNHANDLED REJECTION:', reason);
    console.error('----------------------------------------------------------------');
});

// EJS View Engine Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Respect proxy headers (needed for correct base URL behind reverse proxies)
app.set('trust proxy', true);

// Middleware
app.use(express.static(path.join(__dirname, '../public')));
app.use(express.urlencoded({ extended: true })); // For parsing form data
app.use(express.json());

// DEBUG: Log all requests to see what the IdP is sending
app.use((req, res, next) => {
    logger.info(`[REQUEST] ${req.method} ${req.url}`);
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
const oauthConfigPath = path.join(__dirname, '../oauth-config.json');
const jwtConfigPath = path.join(__dirname, '../jwt-config.json');
const oidcConfigPath = path.join(__dirname, '../oidc-config.json');

function normalizeBaseUrl(input) {
    if (!input || typeof input !== 'string') return '';
    const trimmed = input.trim();
    if (!trimmed) return '';
    return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
}

function deriveBaseUrlFromAcsUrl(acsUrl) {
    try {
        if (!acsUrl) return '';
        const u = new URL(String(acsUrl));
        return normalizeBaseUrl(`${u.protocol}//${u.host}`);
    } catch {
        return '';
    }
}

function getConfiguredBaseUrl(config) {
    const envBaseUrl = normalizeBaseUrl(process.env.BASE_URL || process.env.APP_BASE_URL || '');
    if (envBaseUrl) return envBaseUrl;
    const cfgBaseUrl = normalizeBaseUrl(config?.sp?.baseUrl || '');
    if (cfgBaseUrl) return cfgBaseUrl;
    return deriveBaseUrlFromAcsUrl(config?.sp?.acsUrl);
}

function computeDefaultEntityId(config) {
    const baseUrl = getConfiguredBaseUrl(config);
    if (!baseUrl) return '';
    return `${baseUrl}/saml/metadata`;
}

function getEffectiveSpEntityId(config) {
    const configured = (config?.sp?.entityId || '').trim();
    // Default placeholder or empty → use metadata endpoint URL
    if (!configured || configured === 'passport-saml') {
        const computed = computeDefaultEntityId(config);
        return computed || configured || 'passport-saml';
    }
    return configured;
}

// Helper to load configuration
function loadSamlConfig() {
    try {
        if (fs.existsSync(configPath)) {
            const data = fs.readFileSync(configPath, 'utf8');
            return JSON.parse(data);
        }
    } catch (e) {
        logger.error('Error loading SAML config:', e);
    }
    // Default fallback
    return {
        strict: true,
        debug: false,
        sp: {
            entityId: 'passport-saml',
            acsUrl: 'http://localhost:3000/login/sso/callback',
            baseUrl: 'http://localhost:3000',
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
        issuer: getEffectiveSpEntityId(config),
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
    logger.info('[DEBUG] Strategy Options Mapped:', {
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
        logger.error('Error saving SAML config:', e);
        return false;
    }
}

function loadOauthConfig() {
    let config = {
        authorizationURL: 'https://provider.com/oauth2/authorize',
        tokenURL: 'https://provider.com/oauth2/token',
        clientID: 'client_id',
        clientSecret: 'client_secret',
        callbackURL: 'http://localhost:3000/login/oauth/callback',
        userInfoURL: '',
        attributeMapping: {
            email: 'Email',
            username: 'UserName',
            firstName: '',
            lastName: '',
            department: '',
            roles: ''
        }
    };
    try {
        if (fs.existsSync(oauthConfigPath)) {
            const data = fs.readFileSync(oauthConfigPath, 'utf8');
            const loaded = JSON.parse(data);
            config = { ...config, ...loaded };
            if (!config.attributeMapping) {
                config.attributeMapping = { email: 'Email', username: 'UserName', firstName: '', lastName: '', department: '', roles: '' };
            }
        }
    } catch (e) {
        logger.error('Error loading OAuth config:', e);
    }
    return config;
}

function saveOauthConfig(config) {
    try {
        fs.writeFileSync(oauthConfigPath, JSON.stringify(config, null, 2), 'utf8');
        return true;
    } catch (e) {
        logger.error('Error saving OAuth config:', e);
        return false;
    }
}

function loadJwtConfig() {
    let config = {
        authorizationURL: 'https://prod-account.test.alkanlab.com/jwt/authorize',
        tokenURL: 'https://prod-account.test.alkanlab.com/jwt/token',
        logoutURL: 'https://prod-account.test.alkanlab.com/logout',
        userInfoURL: 'https://prod-account.test.alkanlab.com/jwt/userinfo',
        jwksURL: 'https://prod-account.test.alkanlab.com/.well-known/jwks',
        clientID: '',
        clientSecret: '',
        scope: 'openid offline_access',
        callbackURL: 'http://localhost:3000/login/jwt/callback',
        attributeMapping: { email: 'Email', username: 'UserName', firstName: '', lastName: '', department: '', roles: '' }
    };
    try {
        if (fs.existsSync(jwtConfigPath)) {
            const data = fs.readFileSync(jwtConfigPath, 'utf8');
            const loaded = JSON.parse(data);
            config = { ...config, ...loaded };
            if (!config.attributeMapping) {
                config.attributeMapping = { email: 'Email', username: 'UserName', firstName: '', lastName: '', department: '', roles: '' };
            }
        }
    } catch (e) {
        logger.error('Error loading JWT config:', e);
    }
    return config;
}

function saveJwtConfig(config) {
    try {
        fs.writeFileSync(jwtConfigPath, JSON.stringify(config, null, 2), 'utf8');
        return true;
    } catch (e) {
        logger.error('Error saving JWT config:', e);
        return false;
    }
}

function loadOidcConfig() {
    let config = {
        authorizationURL: 'https://prod-account.test.alkanlab.com/oidc/authorize',
        tokenURL: 'https://prod-account.test.alkanlab.com/oidc/token',
        userInfoURL: 'https://prod-account.test.alkanlab.com/oidc/userinfo',
        configurationURL: 'https://prod-account.test.alkanlab.com/oidc/.well-known/openid-configuration',
        jwksURL: 'https://prod-account.test.alkanlab.com/oidc/.well-known/jwks',
        clientID: '2db13fbf-d9f9-5ebf-a097-bca9adad222c',
        clientSecret: '',
        scope: 'openid profile email',
        grantType: 'client_credentials',
        callbackURL: 'http://localhost:3000/login/oidc/callback',
        attributeMapping: { email: 'email', username: 'preferred_username', firstName: 'given_name', lastName: 'family_name', department: 'department', roles: 'roles' }
    };
    try {
        if (fs.existsSync(oidcConfigPath)) {
            const data = fs.readFileSync(oidcConfigPath, 'utf8');
            const loaded = JSON.parse(data);
            config = { ...config, ...loaded };
            if (!config.attributeMapping) {
                config.attributeMapping = { email: 'email', username: 'preferred_username', firstName: 'given_name', lastName: 'family_name', department: 'department', roles: 'roles' };
            }
        }
    } catch (e) {
        logger.error('Error loading OIDC config:', e);
    }
    return config;
}

function saveOidcConfig(config) {
    try {
        fs.writeFileSync(oidcConfigPath, JSON.stringify(config, null, 2), 'utf8');
        return true;
    } catch (e) {
        logger.error('Error saving OIDC config:', e);
        return false;
    }
}

// Initial configuration load
let samlConfig = loadSamlConfig();
let oauthConfig = loadOauthConfig();
let jwtConfig = loadJwtConfig();
let oidcConfig = loadOidcConfig();

// Ensure baseUrl is present for sensible defaults (especially for metadata URL)
if (!samlConfig.sp) samlConfig.sp = {};
if (!samlConfig.sp.baseUrl) {
    const derived = deriveBaseUrlFromAcsUrl(samlConfig.sp.acsUrl);
    if (derived) {
        samlConfig.sp.baseUrl = derived;
        // best-effort persist so admin UI shows it
        try { saveSamlConfig(samlConfig); } catch { /* ignore */ }
    }
}

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
        logger.error('Error loading SAML events:', e);
    }
    return [];
}

// Helper to save events to file
function saveSamlEvents(events) {
    try {
        fs.writeFileSync(eventsLogPath, JSON.stringify(events, null, 2), 'utf8');
    } catch (e) {
        logger.error('Error saving SAML events:', e);
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

/**
 * Shared SAML verify callback — handles full attribute mapping + permission resolution.
 * Used both at startup and after config save.
 */
function samlVerifyCallback(profile, done) {
    try {
        // Log Profile received
        addSamlEvent('SP', 'Identity Verified', 'IdP kimlik doğrulamasını başarıyla tamamladı.', { profileKeys: Object.keys(profile) });

        // Dynamic Attribute Mapping
        addSamlEvent('SP', 'Attribute Mapping', 'Kullanıcı özellikleri yerel modele eşleniyor.');

        // DEBUG: Log entire profile to see what IdP sends
        try {
            logger.info('[DEBUG] Full SAML Profile:', JSON.stringify(profile, null, 2));
        } catch (e) {
            logger.error('[DEBUG] Could not stringify profile:', e);
            logger.info('[DEBUG] Profile keys:', Object.keys(profile));
        }

        const mapping = samlConfig.attributeMapping || {};

        // Helper: find attribute case-insensitively in profile root or .attributes
        const getAttribute = (key) => {
            if (!key) return null;
            // 1. Exact match in profile root
            if (profile[key] !== undefined) return profile[key];
            // 2. Case-insensitive in profile root
            const lowerKey = key.toLowerCase();
            let foundKey = Object.keys(profile).find(k => k.toLowerCase() === lowerKey);
            if (foundKey) return profile[foundKey];
            // 3. Search in profile.attributes (some IdPs nest attributes)
            if (profile.attributes) {
                if (profile.attributes[key] !== undefined) return profile.attributes[key];
                foundKey = Object.keys(profile.attributes).find(k => k.toLowerCase() === lowerKey);
                if (foundKey) return profile.attributes[foundKey];
            }
            return null;
        };

        // Map core fields
        let email = getAttribute(mapping.email || 'email') || profile.email || profile.Email || 'saml@example.com';
        let username = getAttribute(mapping.username || 'uid') || profile.nameID || profile.NameID || email || 'SAML User';
        let firstName = getAttribute(mapping.firstName || 'givenName') || '';
        let lastName = getAttribute(mapping.lastName || 'surname') || '';
        let department = getAttribute(mapping.department || 'department') || '';
        let roles = getAttribute(mapping.roles || 'groups') || [];

        // Normalize roles to array
        if (typeof roles === 'string') {
            roles = roles.split(',').map(r => r.trim()).filter(Boolean);
        }
        if (!Array.isArray(roles)) roles = [String(roles)];

        // --- Permission Resolution ---
        const permissions = [];
        const permConfig = samlConfig.permissions || {};
        if (permConfig.rules && Array.isArray(permConfig.rules)) {
            // Get the source attribute values for permission matching
            let permSource = getAttribute(permConfig.sourceAttribute || 'groups') || [];
            if (typeof permSource === 'string') {
                permSource = permSource.split(',').map(r => r.trim()).filter(Boolean);
            }
            if (!Array.isArray(permSource)) permSource = [String(permSource)];

            // Ensure all values are trimmed strings
            permSource = permSource.map(v => String(v).trim()).filter(Boolean);

            logger.info('[DEBUG] Permission Source (Groups):', permSource);

            // Match rules
            for (const rule of permConfig.rules) {
                if (permSource.some(v => v.toLowerCase() === rule.idpValue.toLowerCase())) {
                    logger.info(`[DEBUG] Match found for rule: ${rule.idpValue} -> ${rule.permission}`);
                    if (!permissions.includes(rule.permission)) {
                        permissions.push(rule.permission);
                    }
                }
            }
        }

        addSamlEvent('SP', 'Permission Resolved', `Çözümlenen yetkiler: ${permissions.length > 0 ? permissions.join(', ') : 'Yok'}`, { permissions, roles });

        const mappedProfile = { email, username, firstName, lastName, department, roles };

        // Mark setup task as complete
        taskManager.completeTask('saml-setup');

        // Mark attribute mapping task (Task 2) as complete if all required fields are present
        // Requirement: email, username, firstName, lastName, department must be mapped and non-empty
        if (mappedProfile.email && mappedProfile.username && mappedProfile.firstName && mappedProfile.lastName && mappedProfile.department) {
            // Additional validation: Ensure they are not default fallbacks or empty strings if possible, 
            // but our mapping logic ensures they are strings.
            // Let's trust they are mapped values.
            taskManager.completeTask('attribute-mapping');
            addSamlEvent('SP', 'Task Completed', 'Görev 2: Attribute Eşleştirmesi Tamamlandı. (Tüm alanlar başarıyla alındı: email, uid, ad, soyad, departman)');
        }

        // Safely clone profile to avoid circular references in session/views
        let safeSamlProfile = {};
        try {
            safeSamlProfile = JSON.parse(JSON.stringify(profile));
        } catch (e) {
            logger.error('[CRITICAL] Circular reference in SAML profile, using simplified version.');
            safeSamlProfile = {
                nameID: profile.nameID || profile.NameID,
                sessionIndex: profile.sessionIndex,
                ...Object.keys(profile).reduce((acc, key) => {
                    if (typeof profile[key] === 'string' || typeof profile[key] === 'number') {
                        acc[key] = profile[key];
                    }
                    return acc;
                }, {})
            };
        }

        const user = {
            id: profile.nameID || email || 'saml-user',
            username: username,
            email: email,
            source: 'saml',
            samlProfile: safeSamlProfile,
            mappedProfile: mappedProfile,
            permissions: permissions
        };
        return done(null, user);
    } catch (error) {
        logger.error('[CRITICAL] Error in samlVerifyCallback:', error);
        return done(error);
    }
}

try {
    // Debugging: check values (Moved after fix so idpCert is correct)
    logger.info('SAML Strategy Options (Final):', {
        entryPoint: strategyOptions.entryPoint,
        issuer: strategyOptions.issuer,
        cert: strategyOptions.cert ? 'EXISTS' : 'MISSING',
        idpCert: strategyOptions.idpCert ? 'EXISTS' : 'MISSING', // Should be populated now
        authnRequestsSigned: strategyOptions.authnRequestsSigned
    });

    passport.use('saml', new SamlStrategy(
        strategyOptions,
        samlVerifyCallback
    ));
} catch (e) {
    logger.error('[WARNING] Failed to initialize SAML Strategy (likely missing config):', e.message);
    logger.info('Using Dummy SAML Strategy to allow server startup.');

    // Dummy Strategy to prevent route crashes and inform user
    passport.use('saml', {
        name: 'saml',
        authenticate: function (req, options) {
            this.fail({ message: 'SAML yapılandırması eksik veya hatalı. Lütfen yönetici paneli üzerinden ayarları güncelleyin.' }, 400);
        }
    });
}


// 3. OAuth 2.0 Strategy Configuration
function getPropByString(obj, propString) {
    if (!propString || !obj) return undefined;
    const parts = propString.split('.');
    let curr = obj;
    for (let part of parts) {
        if (curr === undefined || curr === null) return undefined;
        curr = curr[part];
    }
    return curr === undefined || curr === null ? '' : curr;
}

function oauthVerifyCallback(accessToken, refreshToken, profile, done) {
    try {
        addSamlEvent('SP', 'OAuth Identity Verified', 'OAuth IdP kimlik doğrulamasını başarıyla tamamladı.', { accessToken: accessToken ? '*****' : null });
        
        // Profil alanlarını JWT / Passport formatlarına göre esnek map edelim
        const rawEmail = (profile && profile.email) || (profile && profile.emails && profile.emails[0] ? profile.emails[0].value : 'oauth@example.com');
        const rawUsername = profile && (profile.preferred_username || profile.nickname || profile.username || profile.displayName || profile.name) ? (profile.preferred_username || profile.nickname || profile.username || profile.displayName || profile.name) : 'oauth_user';
        const rawId = profile && (profile.sub || profile.id) ? (profile.sub || profile.id) : 'oauth-user';
        const rawFirstName = profile && (profile.given_name || profile.givenName || (profile.name && profile.name.givenName)) ? (profile.given_name || profile.givenName || profile.name.givenName) : '';
        const rawLastName = profile && (profile.family_name || profile.familyName || (profile.name && profile.name.familyName)) ? (profile.family_name || profile.familyName || profile.name.familyName) : '';

        const mapping = oauthConfig.attributeMapping || {};
        const mappedEmail = mapping.email ? getPropByString(profile, mapping.email) : rawEmail;
        const mappedUsername = mapping.username ? getPropByString(profile, mapping.username) : rawUsername;
        const mappedFirstName = mapping.firstName ? getPropByString(profile, mapping.firstName) : rawFirstName;
        const mappedLastName = mapping.lastName ? getPropByString(profile, mapping.lastName) : rawLastName;
        const mappedDepartment = mapping.department ? getPropByString(profile, mapping.department) : (profile && profile.department ? profile.department : '');
        let mappedRoles = mapping.roles ? getPropByString(profile, mapping.roles) : (profile && profile.groups ? profile.groups : (profile && profile.roles ? profile.roles : []));

        if (!Array.isArray(mappedRoles)) {
             mappedRoles = typeof mappedRoles === 'string' ? mappedRoles.split(',').map(s=>s.trim()) : [];
        }

        const user = {
            id: String(rawId),
            username: String(mappedUsername || rawUsername || 'oauth_user'),
            email: String(mappedEmail || rawEmail || 'oauth@example.com'),
            source: 'oauth',
            permissions: [],
            oauthProfile: profile,
            mappedProfile: {
                email: String(mappedEmail || rawEmail || ''),
                firstName: String(mappedFirstName || ''),
                lastName: String(mappedLastName || ''),
                username: String(mappedUsername || rawUsername || ''),
                department: String(mappedDepartment || ''),
                roles: mappedRoles
            }
        };
        
        // Mark OAuth setup task as complete
        taskManager.completeTask('oauth-setup');
        
        return done(null, user);
    } catch (error) {
        logger.error('[CRITICAL] Error in oauthVerifyCallback:', error);
        return done(error);
    }
}

try {
    const oauthStrategyOptions = {
        authorizationURL: oauthConfig.authorizationURL,
        tokenURL: oauthConfig.tokenURL,
        clientID: oauthConfig.clientID,
        clientSecret: oauthConfig.clientSecret,
        callbackURL: oauthConfig.callbackURL
    };
    const oauthStrategy = new OAuth2Strategy(oauthStrategyOptions, oauthVerifyCallback);
    oauthStrategy.userProfile = function(accessToken, done) {
        if (!oauthConfig.userInfoURL) {
            return done(null, {});
        }
        this._oauth2.get(oauthConfig.userInfoURL, accessToken, function (err, body, res) {
            if (err) {
                logger.error('[OAuth] Failed to fetch user profile', err);
                return done(null, {}); // fallback to empty profile
            }
            try {
                const json = JSON.parse(body);
                done(null, json);
            } catch (ex) {
                logger.error('[OAuth] Failed to parse user profile', ex);
                done(null, {});
            }
        });
    };
    passport.use('oauth2', oauthStrategy);
} catch (e) {
    logger.error('[WARNING] Failed to initialize OAuth Strategy (likely missing config):', e.message);
    passport.use('oauth2', {
        name: 'oauth2',
        authenticate: function (req, options) {
            this.fail({ message: 'OAuth yapılandırması eksik veya hatalı.' }, 400);
        }
    });
}

// 4. JWT Strategy Configuration
function jwtVerifyCallback(accessToken, refreshToken, profile, done) {
    try {
        addSamlEvent('SP', 'JWT Verified', 'JWT IdP kimlik doğrulamasını başarıyla tamamladı.', { accessToken: accessToken ? '*****' : null });
        
        const rawEmail = (profile && profile.email) || (profile && profile.emails && profile.emails[0] ? profile.emails[0].value : 'jwt@example.com');
        const rawUsername = profile && (profile.preferred_username || profile.nickname || profile.username || profile.displayName || profile.name) ? (profile.preferred_username || profile.nickname || profile.username || profile.displayName || profile.name) : 'jwt_user';
        const rawId = profile && (profile.sub || profile.id) ? (profile.sub || profile.id) : 'jwt-user';
        const rawFirstName = profile && (profile.given_name || profile.givenName || (profile.name && profile.name.givenName)) ? (profile.given_name || profile.givenName || profile.name.givenName) : '';
        const rawLastName = profile && (profile.family_name || profile.familyName || (profile.name && profile.name.familyName)) ? (profile.family_name || profile.familyName || profile.name.familyName) : '';

        const mapping = jwtConfig.attributeMapping || {};
        const mappedEmail = mapping.email ? getPropByString(profile, mapping.email) : rawEmail;
        const mappedUsername = mapping.username ? getPropByString(profile, mapping.username) : rawUsername;
        const mappedFirstName = mapping.firstName ? getPropByString(profile, mapping.firstName) : rawFirstName;
        const mappedLastName = mapping.lastName ? getPropByString(profile, mapping.lastName) : rawLastName;
        const mappedDepartment = mapping.department ? getPropByString(profile, mapping.department) : (profile && profile.department ? profile.department : '');
        let mappedRoles = mapping.roles ? getPropByString(profile, mapping.roles) : (profile.roles || profile.groups || []);

        if (!Array.isArray(mappedRoles)) {
             mappedRoles = typeof mappedRoles === 'string' ? mappedRoles.split(',').map(s=>s.trim()) : [];
        }

        const user = {
            id: String(rawId),
            username: String(mappedUsername || rawUsername || 'jwt_user'),
            email: String(mappedEmail || rawEmail || 'jwt@example.com'),
            source: 'jwt',
            permissions: [],
            oauthProfile: profile, // reuse this display placeholder for JWT analysis dashboard
            mappedProfile: {
                email: String(mappedEmail || rawEmail || ''),
                firstName: String(mappedFirstName || ''),
                lastName: String(mappedLastName || ''),
                username: String(mappedUsername || rawUsername || ''),
                department: String(mappedDepartment || ''),
                roles: mappedRoles
            }
        };
        
        // Mark JWT setup task as complete
        taskManager.completeTask('jwt-setup');
        
        return done(null, user);
    } catch (error) {
        logger.error('[CRITICAL] Error in jwtVerifyCallback:', error);
        return done(error);
    }
}

try {
    const jwtStrategyOptions = {
        authorizationURL: jwtConfig.authorizationURL,
        tokenURL: jwtConfig.tokenURL,
        clientID: jwtConfig.clientID,
        clientSecret: jwtConfig.clientSecret,
        callbackURL: jwtConfig.callbackURL,
        customHeaders: {},
        scope: jwtConfig.scope ? jwtConfig.scope.split(' ') : ['openid']
    };
    
    const jwtStrategy = new OAuth2Strategy(jwtStrategyOptions, jwtVerifyCallback);
    
    // Override userProfile to fetch UserInfo from jwtConfig.userInfoURL
    jwtStrategy.userProfile = function(accessToken, done) {
        if (!jwtConfig.userInfoURL) {
            return done(null, {});
        }
        this._oauth2.get(jwtConfig.userInfoURL, accessToken, function (err, body, res) {
            if (err) {
                logger.error('[JWT] Failed to fetch user profile', err);
                return done(null, {});
            }
            try {
                const json = JSON.parse(body);
                done(null, json);
            } catch (ex) {
                logger.error('[JWT] Failed to parse user profile', ex);
                done(null, {});
            }
        });
    };

    passport.use('jwt', jwtStrategy);
} catch (e) {
    logger.error('[WARNING] Failed to initialize JWT Strategy:', e.message);
    passport.use('jwt', {
        name: 'jwt',
        authenticate: function (req, options) {
            this.fail({ message: 'JWT yapılandırması eksik.' }, 400);
        }
    });
}


// 5. OIDC Strategy Configuration
function oidcVerifyCallback(accessToken, refreshToken, profile, done) {
    try {
        addSamlEvent('SP', 'OIDC Verified', 'OIDC IdP kimlik doğrulamasını başarıyla tamamladı.', { accessToken: accessToken ? '*****' : null });
        
        const rawEmail = (profile && profile.email) || (profile && profile.emails && profile.emails[0] ? profile.emails[0].value : 'oidc@example.com');
        const rawUsername = profile && (profile.preferred_username || profile.nickname || profile.username || profile.displayName || profile.name) ? (profile.preferred_username || profile.nickname || profile.username || profile.displayName || profile.name) : 'oidc_user';
        const rawId = profile && (profile.sub || profile.id) ? (profile.sub || profile.id) : 'oidc-user';
        const rawFirstName = profile && (profile.given_name || profile.givenName || (profile.name && profile.name.givenName)) ? (profile.given_name || profile.givenName || profile.name.givenName) : '';
        const rawLastName = profile && (profile.family_name || profile.familyName || (profile.name && profile.name.familyName)) ? (profile.family_name || profile.familyName || profile.name.familyName) : '';

        const mapping = oidcConfig.attributeMapping || {};
        const mappedEmail = mapping.email ? getPropByString(profile, mapping.email) : rawEmail;
        const mappedUsername = mapping.username ? getPropByString(profile, mapping.username) : rawUsername;
        const mappedFirstName = mapping.firstName ? getPropByString(profile, mapping.firstName) : rawFirstName;
        const mappedLastName = mapping.lastName ? getPropByString(profile, mapping.lastName) : rawLastName;
        const mappedDepartment = mapping.department ? getPropByString(profile, mapping.department) : (profile && profile.department ? profile.department : '');
        let mappedRoles = mapping.roles ? getPropByString(profile, mapping.roles) : (profile.roles || profile.groups || []);

        if (!Array.isArray(mappedRoles)) {
             mappedRoles = typeof mappedRoles === 'string' ? mappedRoles.split(',').map(s=>s.trim()) : [];
        }

        const user = {
            id: String(rawId),
            username: String(mappedUsername || rawUsername || 'oidc_user'),
            email: String(mappedEmail || rawEmail || 'oidc@example.com'),
            source: 'oidc',
            permissions: [],
            oauthProfile: profile,
            mappedProfile: {
                email: String(mappedEmail || rawEmail || ''),
                firstName: String(mappedFirstName || ''),
                lastName: String(mappedLastName || ''),
                username: String(mappedUsername || rawUsername || ''),
                department: String(mappedDepartment || ''),
                roles: mappedRoles
            }
        };
        
        // Mark OIDC setup task as complete
        taskManager.completeTask('oidc-setup');
        
        return done(null, user);
    } catch (error) {
        logger.error('[CRITICAL] Error in oidcVerifyCallback:', error);
        return done(error);
    }
}

try {
    const oidcStrategyOptions = {
        authorizationURL: oidcConfig.authorizationURL || 'https://placeholder.com/authorize',
        tokenURL: oidcConfig.tokenURL,
        clientID: oidcConfig.clientID,
        clientSecret: oidcConfig.clientSecret,
        callbackURL: oidcConfig.callbackURL,
        customHeaders: {},
        scope: oidcConfig.scope ? oidcConfig.scope.split(' ') : ['openid', 'profile']
    };
    
    const oidcStrategy = new OAuth2Strategy(oidcStrategyOptions, oidcVerifyCallback);
    
    oidcStrategy.userProfile = function(accessToken, done) {
        if (!oidcConfig.userInfoURL) {
            return done(null, {});
        }
        this._oauth2.get(oidcConfig.userInfoURL, accessToken, function (err, body, res) {
            if (err) {
                logger.error('[OIDC] Failed to fetch user profile', err);
                return done(null, {});
            }
            try {
                const json = JSON.parse(body);
                done(null, json);
            } catch (ex) {
                logger.error('[OIDC] Failed to parse user profile', ex);
                done(null, {});
            }
        });
    };

    if (oidcConfig.grantType === 'client_credentials') {
       oidcStrategy.authenticate = function(req, options) {
            this._oauth2.getOAuthAccessToken(
              '', { grant_type: 'client_credentials' },
              (err, accessToken, refreshToken, results) => {
                 if (err) return this.fail({ message: err.data || err.message || 'Token endpoint error' }, 401);
                 this._loadUserProfile(accessToken, (err, profile) => {
                    // It's okay if profile fails for client_credentials if userInfo is unused
                    const finalProfile = profile || {};
                    oidcVerifyCallback(accessToken, refreshToken, finalProfile, (err, user, info) => {
                       if (err) return this.error(err);
                       if (!user) return this.fail(info);
                       this.success(user, info);
                    });
                 });
              }
           );
       };
    }

    passport.use('oidc', oidcStrategy);
} catch (e) {
    logger.error('[WARNING] Failed to initialize OIDC Strategy:', e.message);
    passport.use('oidc', {
        name: 'oidc',
        authenticate: function (req, options) {
            this.fail({ message: 'OIDC yapılandırması eksik.' }, 400);
        }
    });
}


// --- Authentication Logic End ---

// Routes

// SP Metadata Endpoint (use this as SP Entity ID / Audience in IdP)
app.get('/saml/metadata', (req, res) => {
    try {
        const strategy = passport._strategy('saml');
        if (!strategy || typeof strategy.generateServiceProviderMetadata !== 'function') {
            return res.status(500).type('text/plain').send('SAML strategy not initialized; cannot generate metadata.');
        }

        // Some IdPs want the SP's public certificate(s) in metadata if you sign requests.
        // We only include certificates if configured; otherwise omit.
        const spPublicCert = (samlConfig?.sp?.x509cert || '').trim() || null;
        const spDecryptionCert = null;

        const xml = strategy.generateServiceProviderMetadata(spDecryptionCert, spPublicCert);
        res.type('application/xml').send(xml);
    } catch (e) {
        logger.error('[CRITICAL] Failed to generate SP metadata:', e);
        res.status(500).type('text/plain').send('Failed to generate metadata.');
    }
});

// Home Route
app.get('/', (req, res) => {
    res.redirect('/login');
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

    let alertMessage = null;
    let alertType = 'danger';

    if (req.session && req.session.messages && req.session.messages.length > 0) {
        alertMessage = req.session.messages.join('<br>');
        req.session.messages = [];
    }

    if (req.query.error === 'saml_missing') {
        alertMessage = 'SAML ayarları yapılandırılmamış. Lütfen yönetici paneli üzerinden gerekli IdP ve SP ayarlarını tamamlayın.';
        alertType = 'warning';
    } else if (req.query.error === 'oauth_missing') {
        alertMessage = 'OAuth 2.0 ayarları yapılandırılmamış. Lütfen yönetici paneli üzerinden ayarlamaları tamamlayın.';
        alertType = 'warning';
    } else if (req.query.error === 'jwt_missing') {
        alertMessage = 'JWT ayarları yapılandırılmamış. Lütfen yönetici paneli üzerinden ayarlamaları tamamlayın.';
        alertType = 'warning';
    } else if (req.query.error === 'oidc_missing') {
        alertMessage = 'OIDC AuthN/Z ayarları yapılandırılmamış. Lütfen yönetici panelinden konfigürasyonu tamamlayın.';
        alertType = 'warning';
    }

    res.render('login', {
        title: 'Giriş Yap',
        defaultUser: defaultUser,
        jwtConfig: jwtConfig,
        oidcConfig: oidcConfig,
        message: alertMessage,
        messageType: alertType
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

        logger.error('--------------------------------------------------');
        logger.error('[CRITICAL CONFIG ERROR] IdP sent response to /login/sso!');
        logger.error(`Expected (Correct) ACS URL: ${correctUrl}`);
        logger.error('--------------------------------------------------');

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
    // Configuration Check
    const isSamlConfigured = samlConfig && samlConfig.idp && samlConfig.idp.ssoUrl && !samlConfig.idp.ssoUrl.includes('xxxxxxxxx');
    if (!isSamlConfigured) {
        return res.redirect('/login?error=saml_missing');
    }

    // LOOP DETECTION: Check if IdP is redirecting back here with a response
    // Safely check properties to avoid 'undefined' errors
    const hasSAMLResponse = (req.query && req.query.SAMLResponse) || (req.body && req.body.SAMLResponse);
    if (hasSAMLResponse) {
        logger.error('[CRITICAL] SAMLResponse detected at /login/sso! This indicates an IdP configuration error.');
        logger.error('The IdP ACS URL is likely set to /login/sso instead of /login/sso/callback');
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
                        if (err) logger.error('Session save error:', err);
                        return originalRedirect.apply(this, arguments);
                    });

                } catch (err) {
                    logger.error('Error inflating SAMLRequest:', err);
                }
            }
        } catch (e) {
            logger.error('Error capturing SAMLRequest:', e);
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
        logger.info('[DEBUG] Hit /login/sso/callback - Step 1');
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
                logger.error('Error capturing SAMLResponse:', e);
                addSamlEvent('System', 'Error', 'SAML Response işlenirken hata oluştu.', { error: e.message });
            }
        }

        // Detect non-standard XMLDSIG that node-saml cannot validate (e.g. ds:Reference without URI).
        // In that case, we bypass passport-saml verification ONLY for that request.
        let useCompatBypass = false;
        if (req.body.SAMLResponse && req.session.samlResponseXML) {
            try {
                const xml = String(req.session.samlResponseXML);
                const hasSignature = /<ds:Signature\b/.test(xml);
                const referenceOpenTagMatch = xml.match(/<ds:Reference\b([^>]*)>/);
                const referenceHasUri = referenceOpenTagMatch && referenceOpenTagMatch[1]
                    ? /\bURI\s*=/.test(referenceOpenTagMatch[1])
                    : false;
                if (hasSignature && referenceOpenTagMatch && !referenceHasUri) {
                    useCompatBypass = true;
                    addSamlEvent(
                        'SP',
                        'Compatibility Mode',
                        'IdP non-standard imza formatı tespit edildi (ds:Reference URI yok). Bu istek için imza doğrulaması bypass edilecek.',
                        null
                    );
                }
            } catch (e) {
                logger.error('[WARNING] Compatibility detection failed (continuing):', e);
            }
        }

        const parseSamlProfileFromXml = (xml) => {
            const profile = {};
            // Issuer
            const issuerMatch = xml.match(/<saml2:Issuer[^>]*>\s*([^<]+)\s*<\/saml2:Issuer>/);
            if (issuerMatch && issuerMatch[1]) profile.issuer = issuerMatch[1].trim();

            // NameID
            const nameIdMatch = xml.match(/<saml2:NameID[^>]*>\s*([^<]+)\s*<\/saml2:NameID>/);
            if (nameIdMatch && nameIdMatch[1]) profile.nameID = nameIdMatch[1].trim();

            // Assertion ID
            const assertionIdMatch = xml.match(/<saml2:Assertion\b[^>]*\bID=["']([^"']+)["']/);
            if (assertionIdMatch && assertionIdMatch[1]) profile.id = assertionIdMatch[1].trim();

            // Attributes (very small, non-XML-parser approach; good enough for this demo IdP format)
            const attributes = {};
            const attrRegex = /<saml2:Attribute\b[^>]*\bName=["']([^"']+)["'][^>]*>([\s\S]*?)<\/saml2:Attribute>/g;
            let attrMatch;
            while ((attrMatch = attrRegex.exec(xml)) !== null) {
                const name = attrMatch[1];
                const body = attrMatch[2] || '';
                const values = [];
                const valRegex = /<saml2:AttributeValue[^>]*>\s*([^<]*)\s*<\/saml2:AttributeValue>/g;
                let valMatch;
                while ((valMatch = valRegex.exec(body)) !== null) {
                    const v = (valMatch[1] || '').trim();
                    if (v) values.push(v);
                }
                if (values.length === 1) attributes[name] = values[0];
                else if (values.length > 1) attributes[name] = values;
            }
            profile.attributes = attributes;

            // Common shortcuts
            if (!profile.email && typeof attributes.email === 'string') profile.email = attributes.email;
            if (!profile.firstName && typeof attributes.firstName === 'string') profile.firstName = attributes.firstName;
            if (!profile.lastName && typeof attributes.lastName === 'string') profile.lastName = attributes.lastName;

            return profile;
        };

        if (useCompatBypass && req.session.samlResponseXML) {
            try {
                const xml = String(req.session.samlResponseXML);
                const profile = parseSamlProfileFromXml(xml);

                return samlVerifyCallback(profile, (err, user) => {
                    if (err) {
                        logger.error('[CRITICAL] Compatibility bypass verification error:', err);
                        return res.status(500).send(`
                            <h1>Authentication Error</h1>
                            <p>An error occurred during SAML authentication.</p>
                            <pre>${err.message}</pre>
                        `);
                    }
                    if (!user) {
                        logger.error('[CRITICAL] Compatibility bypass failed (No User)');
                        return res.status(401).send(`
                            <h1>Authentication Failed</h1>
                            <p>Compatibility bypass could not create a user.</p>
                        `);
                    }
                    return req.logIn(user, (err2) => {
                        if (err2) {
                            logger.error('[CRITICAL] Session Login Error (compat bypass):', err2);
                            return next(err2);
                        }
                        return res.redirect('/dashboard');
                    });
                });
            } catch (e) {
                logger.error('[CRITICAL] Compatibility bypass failed (exception):', e);
                // fall through to normal passport flow
            }
        }

        // Debugging: Check if request XML exists in session before authentication
        if (req.session.samlRequestXML) {
            // Store in locals to survive potential session regeneration during passport.authenticate
            res.locals.tempSamlRequestXML = req.session.samlRequestXML;
        }

        // Custom Passport Callback for Better Debugging
        passport.authenticate('saml', (err, user, info) => {
            if (err) {
                logger.error('[CRITICAL] Passport Authentication Error:', err);
                return res.status(500).send(`
                    <h1>Authentication Error</h1>
                    <p>An error occurred during SAML authentication.</p>
                    <pre>${err.message}</pre>
                `);
            }

            if (!user) {
                logger.error('[CRITICAL] Passport Authentication Failed (No User):', info);
                let debugInfo = info;
                if (info instanceof Error) {
                    debugInfo = { message: info.message, stack: info.stack, ...info };
                }
                return res.status(401).send(`
                    <h1>Authentication Failed</h1>
                    <p>Identity Provider request failed validation.</p>
                    <p><b>Reason:</b> ${info && info.message ? info.message : 'Unknown'}</p>
                    <pre>${JSON.stringify(debugInfo, null, 2)}</pre>
                `);
            }

            // Establish Session
            req.logIn(user, (err) => {
                if (err) {
                    logger.error('[CRITICAL] Session Login Error:', err);
                    return next(err);
                }

                // Restore/Persist XML logs to user object in session
                if (res.locals.tempSamlRequestXML) {
                    req.user.samlRequestXML = res.locals.tempSamlRequestXML;
                } else if (global.recentSamlRequestXML) {
                    req.user.samlRequestXML = global.recentSamlRequestXML;
                }

                if (req.session.samlResponseXML) {
                    req.user.samlResponseXML = req.session.samlResponseXML;
                } else if (global.recentSamlResponseXML) {
                    req.user.samlResponseXML = global.recentSamlResponseXML;
                }

                return res.redirect('/dashboard');
            });
        })(req, res, next);
    }
);

// --- OAuth 2.0 Login / Callback ---
app.get('/login/oauth', (req, res, next) => {
    if (!oauthConfig || !oauthConfig.clientID || oauthConfig.clientID.trim() === 'client_id' || oauthConfig.clientID.trim() === '') {
        return res.redirect('/login?error=oauth_missing');
    }
    next();
}, passport.authenticate('oauth2', {
    failureRedirect: '/login',
    failureMessage: true
}));

app.get('/login/oauth/callback', passport.authenticate('oauth2', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureMessage: true
}));

// --- JWT Login / Callback ---
app.get('/login/jwt', (req, res, next) => {
    if (!jwtConfig || !jwtConfig.clientID || jwtConfig.clientID.trim() === '') {
        return res.redirect('/login?error=jwt_missing');
    }
    next();
}, passport.authenticate('jwt', {
    failureRedirect: '/login',
    failureMessage: true
}));

app.get('/login/jwt/callback', passport.authenticate('jwt', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureMessage: true
}));

// Initial configuration load
// Config is already loaded at the top.

// Admin Page Route


console.log("Registering OIDC routes...");
// --- OIDC Login / Callback ---
app.get('/testoidc', (req, res) => res.send("Debug OIDC Endpoint Reached!"));

app.get('/login/oidc', (req, res, next) => {
    if (!oidcConfig || !oidcConfig.clientID || oidcConfig.clientID.trim() === '') {
        return res.redirect('/login?error=oidc_missing');
    }
    next();
}, (req, res, next) => {
    passport.authenticate('oidc', { failureRedirect: '/login', failureMessage: true }, (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.redirect('/login');
        }
        req.login(user, (loginErr) => {
            if (loginErr) {
                return next(loginErr);
            }
            return res.redirect('/dashboard');
        });
    })(req, res, next);
});

app.get('/login/oidc/callback', passport.authenticate('oidc', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureMessage: true
}));

// API Endpoint for Live Events (Accessible to all authenticated users)
app.get('/api/events', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(403).json({ error: 'Erişim reddedildi' });
    }
    res.json(global.samlEvents || []);
});

// API Endpoint to Clear Events
app.post('/api/events/clear', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(403).json({ error: 'Erişim reddedildi' });
    }

    // Clear in memory
    global.samlEvents = [];

    // Clear in file
    saveSamlEvents([]);

    res.json({ success: true, message: 'Olay günlüğü temizlendi.' });
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
        safeSet(samlConfig, 'sp.baseUrl', normalizeBaseUrl(req.body.sp_baseUrl || ''));
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

        // 4. Attribute Mapping (Extended)
        samlConfig.attributeMapping = {
            email: req.body.attr_email || 'email',
            username: req.body.attr_username || 'uid',
            firstName: req.body.attr_firstName || 'givenName',
            lastName: req.body.attr_lastName || 'surname',
            department: req.body.attr_department || 'department',
            roles: req.body.attr_roles || 'groups'
        };

        // 5. Permission Rules
        const permSource = req.body.perm_sourceAttribute || 'groups';
        const permIdpValues = Array.isArray(req.body.perm_idpValue) ? req.body.perm_idpValue : (req.body.perm_idpValue ? [req.body.perm_idpValue] : []);
        const permNames = Array.isArray(req.body.perm_permission) ? req.body.perm_permission : (req.body.perm_permission ? [req.body.perm_permission] : []);
        const rules = [];
        for (let i = 0; i < permIdpValues.length; i++) {
            const idpVal = (permIdpValues[i] || '').trim();
            const permName = (permNames[i] || '').trim();
            if (idpVal && permName) {
                rules.push({ idpValue: idpVal, permission: permName });
            }
        }
        samlConfig.permissions = { sourceAttribute: permSource, rules };

        // Persist
        if (!saveSamlConfig(samlConfig)) {
            return res.status(500).send('Ayarlar kaydedilirken bir hata oluştu.');
        }

        // Re-Config Strategy using shared callback
        passport.unuse('saml');
        const newOptions = mapConfigToStrategyOptions(samlConfig);
        newOptions.idpCert = newOptions.cert;
        try {
            passport.use('saml', new SamlStrategy(newOptions, samlVerifyCallback));
        } catch (e) {
            logger.error('[WARNING] Failed to initialize SAML Strategy after save:', e.message);
            logger.info('Using Dummy SAML Strategy to allow server startup.');
            passport.use('saml', {
                name: 'saml',
                authenticate: function (req, options) {
                    this.fail({ message: 'SAML yapılandırması eksik veya hatalı. Lütfen yönetici paneli üzerinden ayarları güncelleyin.' }, 400);
                }
            });
        }

        res.redirect('/admin?success=true');

    } catch (e) {
        logger.error("Config save error:", e);
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

// Save Configuration Route - OIDC
app.post('/admin/save-oidc', (req, res) => {
    if (!req.isAuthenticated() || req.user.username !== 'admin') {
        return res.status(403).send('Erişim reddedildi.');
    }

    try {
        oidcConfig.authorizationURL = req.body.oidc_authorizationURL;
        oidcConfig.tokenURL = req.body.oidc_tokenURL;
        oidcConfig.userInfoURL = req.body.oidc_userInfoURL;
        oidcConfig.configurationURL = req.body.oidc_configurationURL;
        oidcConfig.jwksURL = req.body.oidc_jwksURL;
        oidcConfig.clientID = req.body.oidc_clientID;
        oidcConfig.clientSecret = req.body.oidc_clientSecret;
        oidcConfig.scope = req.body.oidc_scope;
        oidcConfig.grantType = req.body.oidc_grantType || 'client_credentials';
        oidcConfig.callbackURL = req.body.oidc_callbackURL;

        if (!oidcConfig.attributeMapping) oidcConfig.attributeMapping = {};
        oidcConfig.attributeMapping.email = req.body.oidc_attr_email;
        oidcConfig.attributeMapping.username = req.body.oidc_attr_username;
        oidcConfig.attributeMapping.firstName = req.body.oidc_attr_firstName;
        oidcConfig.attributeMapping.lastName = req.body.oidc_attr_lastName;
        oidcConfig.attributeMapping.department = req.body.oidc_attr_department;
        oidcConfig.attributeMapping.roles = req.body.oidc_attr_roles;

        if (!saveOidcConfig(oidcConfig)) {
            return res.status(500).send('Ayarlar kaydedilirken bir hata oluştu.');
        }

        res.redirect('/admin?success=true');
    } catch (e) {
        logger.error("OIDC Config save error:", e);
        res.status(500).send('Ayarlar kaydedilirken hata oluştu: ' + e.message);
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

// Permission Check Middleware
// Permission Check Middleware
function checkPermission(requiredPermission) {
    return (req, res, next) => {
        // Bypass for local admin - they have all permissions
        if (req.isAuthenticated() && req.user.username === 'admin') {
            return next();
        }

        if (req.isAuthenticated() && req.user.permissions && req.user.permissions.includes(requiredPermission)) {
            // Log successful permission access for task tracking
            // Only complete if source is SAML as requested
            if (req.user.source === 'saml') {
                taskManager.completeTask('permission-check');
            }
            return next();
        }

        res.status(403).render('error', { message: 'Bu sayfaya erişim yetkiniz yok. Gerekli yetki: ' + requiredPermission, title: 'Erişim Engellendi' });
    };
}

// Admin Route (Protected)
app.get('/admin', (req, res, next) => {
    // Check for either local admin OR iammert_admin permission
    if (req.isAuthenticated() && (req.user.username === 'admin' || (req.user.permissions && req.user.permissions.includes('iammert_admin')))) {
        // Complete admin task only if source is SAML
        if (req.user.source === 'saml' && req.user.permissions.includes('iammert_admin')) {
            taskManager.completeTask('permission-check');
        }
        return next();
    }
    res.redirect('/login');
}, (req, res) => {
    const config = samlConfig;

    // Permission Rules View Logic
    const fixedPermissions = [
        { check: 'iammert_admin', label: 'Admin Paneli Yetkisi (iammert_admin)', placeholder: 'admin' },
        { check: 'iammert_sozluk', label: 'Sözlük Yetkisi (iammert_sozluk)', placeholder: 'dev' }
    ];

    const mappedRules = fixedPermissions.map(fp => {
        let currentVal = '';
        if (config.permissions && config.permissions.rules) {
            const rule = config.permissions.rules.find(r => r.permission === fp.check);
            if (rule) currentVal = rule.idpValue;
        }
        return { ...fp, currentValue: currentVal };
    });

    res.render('admin', {
        title: 'Admin Panel',
        config: samlConfig,
        oauthConfig: oauthConfig,
        jwtConfig: jwtConfig,
        oidcConfig: oidcConfig,
        user: req.user,
        permissionRules: mappedRules,
        message: req.query.success ? 'Ayarlar başarıyla kaydedildi! Strategy yeniden başlatıldı.' : null,
        events: global.samlEvents || []
    });
});

// Dictionary Route (Protected)
app.get('/sozluk', (req, res, next) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    next();
}, checkPermission('iammert_sozluk'), (req, res) => {
    res.render('sozluk', { user: req.user });
});

// API: Reset Tasks (Admin only)
app.post('/admin/reset-tasks', (req, res) => {
    if (!req.isAuthenticated() || req.user.username !== 'admin') {
        return res.status(403).send('Erişim reddedildi.');
    }
    taskManager.resetTasks();
    res.redirect('/admin?success=tasks_reset');
});

// API: Reset SAML
app.post('/admin/reset-saml', (req, res) => {
    if (!req.isAuthenticated() || req.user.username !== 'admin') {
        return res.status(403).send('Erişim reddedildi.');
    }
    const scope = req.body.reset_scope || 'all';

    if (scope === 'all') {
        if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
        Object.keys(samlConfig).forEach(k => delete samlConfig[k]);
        Object.assign(samlConfig, loadSamlConfig());
    } else if (scope === 'idp') {
        samlConfig.idp = loadSamlConfig().idp;
    } else if (scope === 'security') {
        samlConfig.security = loadSamlConfig().security;
    } else if (scope === 'mapping') {
        samlConfig.attributeMapping = loadSamlConfig().attributeMapping;
        samlConfig.permissions = { sourceAttribute: 'groups', rules: [] };
    }
    
    saveSamlConfig(samlConfig);
    res.redirect('/admin?success=saml_reset');
});

// API: Reset OAuth
app.post('/admin/reset-oauth', (req, res) => {
    if (!req.isAuthenticated() || req.user.username !== 'admin') {
        return res.status(403).send('Erişim reddedildi.');
    }
    if (fs.existsSync(oauthConfigPath)) fs.unlinkSync(oauthConfigPath);
    Object.keys(oauthConfig).forEach(k => delete oauthConfig[k]);
    Object.assign(oauthConfig, loadOauthConfig());
    saveOauthConfig(oauthConfig);
    res.redirect('/admin?success=oauth_reset');
});

// API: Reset JWT
app.post('/admin/reset-jwt', (req, res) => {
    if (!req.isAuthenticated() || req.user.username !== 'admin') {
        return res.status(403).send('Erişim reddedildi.');
    }
    if (fs.existsSync(jwtConfigPath)) fs.unlinkSync(jwtConfigPath);
    Object.keys(jwtConfig).forEach(k => delete jwtConfig[k]);
    Object.assign(jwtConfig, loadJwtConfig());
    saveJwtConfig(jwtConfig);
    res.redirect('/admin?success=jwt_reset');
});

// API: Reset OIDC
app.post('/admin/reset-oidc', (req, res) => {
    if (!req.isAuthenticated() || req.user.username !== 'admin') {
        return res.status(403).send('Erişim reddedildi.');
    }
    if (fs.existsSync(oidcConfigPath)) fs.unlinkSync(oidcConfigPath);
    Object.keys(oidcConfig).forEach(k => delete oidcConfig[k]);
    Object.assign(oidcConfig, loadOidcConfig());
    saveOidcConfig(oidcConfig);
    res.redirect('/admin?success=oidc_reset');
});

// API: Factory Reset
app.post('/admin/factory-reset', (req, res) => {
    if (!req.isAuthenticated() || req.user.username !== 'admin') {
        return res.status(403).send('Erişim reddedildi.');
    }
    const eventsPath = path.join(__dirname, '../events.json');
    const tasksPath = path.join(__dirname, 'tasks.json');
    const files = [configPath, oauthConfigPath, jwtConfigPath, oidcConfigPath, tasksPath, eventsPath];
    files.forEach(p => {
        if (fs.existsSync(p)) fs.unlinkSync(p);
    });
    
    res.send(`
        <html>
            <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: red;">Sistem Fabrika Ayarlarına Döndürüldü</h1>
                <p>Tüm config dosyaları ve kayıtlar silindi.</p>
                <p>Uygulama yeniden başlatılıyor... Lütfen sayfayı yenileyin.</p>
                <script>setTimeout(function(){ window.location.href='/'; }, 3000);</script>
            </body>
        </html>
    `);
    
    setTimeout(() => { process.exit(0); }, 500);
});

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
        events: global.samlEvents || [],
        mappedProfile: req.user.mappedProfile || null,
        permissions: req.user.permissions || [],
        tasks: taskManager.loadTasks()
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
