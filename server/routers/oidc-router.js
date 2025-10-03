const express = require("express");
const { Issuer, generators } = require("openid-client");
const { R } = require("redbean-node");
const router = express.Router();
const { log, genSecret } = require("../../src/util");
const { setting } = require("../util-server");
const { Settings } = require("../settings");
const passwordHash = require("../password-hash");
const User = require("../model/user");
const { UptimeKumaServer } = require("../uptime-kuma-server");

const SESSION_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes
const sessionStore = new Map();

let cachedIssuer;
let cachedIssuerURL;

function createOIDCError(code, message) {
    const error = new Error(message);
    error.oidcCode = code;
    return error;
}

async function getOIDCConfig() {
    const [
        enabled,
        issuer,
        clientId,
        clientSecret,
        scope,
        redirectURI,
        usernameClaim,
        autoCreateUser,
        buttonLabel,
    ] = await Promise.all([
        Settings.get("oidcEnabled"),
        Settings.get("oidcIssuerURL"),
        Settings.get("oidcClientID"),
        Settings.get("oidcClientSecret"),
        Settings.get("oidcScope"),
        Settings.get("oidcRedirectURI"),
        Settings.get("oidcUsernameClaim"),
        Settings.get("oidcAutoCreateUser"),
        Settings.get("oidcButtonLabel"),
    ]);

    return {
        enabled: !!enabled,
        issuer,
        clientId,
        clientSecret,
        scope: scope || "openid profile email",
        redirectURI,
        usernameClaim: usernameClaim || "preferred_username",
        autoCreateUser: !!autoCreateUser,
        buttonLabel,
    };
}

function cleanupExpiredSessions() {
    const now = Date.now();
    for (const [ state, session ] of sessionStore.entries()) {
        if (now - session.createdAt > SESSION_EXPIRY_MS) {
            sessionStore.delete(state);
        }
    }
}

async function resolveRedirectURI(req, configuredURI) {
    if (configuredURI) {
        return configuredURI;
    }

    const trustProxy = await setting("trustProxy");
    const protocolHeader = req.headers["x-forwarded-proto"];
    const hostHeader = req.headers["x-forwarded-host"];

    const protocol = trustProxy && protocolHeader ? protocolHeader : req.protocol;
    const host = trustProxy && hostHeader ? hostHeader : req.get("host");

    return `${protocol}://${host}/auth/oidc/callback`;
}

async function getClient(config) {
    if (!config.issuer || !config.clientId) {
        throw createOIDCError("oidcNotConfigured", "OIDC issuer or client id is not configured");
    }

    try {
        if (!cachedIssuer || cachedIssuerURL !== config.issuer) {
            cachedIssuer = await Issuer.discover(config.issuer);
            cachedIssuerURL = config.issuer;
        }

        return new cachedIssuer.Client({
            client_id: config.clientId,
            client_secret: config.clientSecret || undefined,
        });
    } catch (error) {
        log.error("oidc", "OIDC discovery/client initialization failed", error);
        throw createOIDCError("oidcDiscoveryFailed", error.message || "OIDC discovery failed");
    }
}

async function findActiveUser(username) {
    return await R.findOne("user", " username = ? AND active = 1 ", [
        username,
    ]);
}

async function createUser(username) {
    const user = R.dispense("user");
    user.username = username;
    user.password = await passwordHash.generate(genSecret(32));
    user.active = 1;
    user.twofa_status = 0;
    await R.store(user);
    return user;
}

function validateReturnTo(value) {
    if (!value) {
        return null;
    }

    try {
        const decoded = decodeURIComponent(value);
        if (decoded.startsWith("/") && !decoded.startsWith("//")) {
            return decoded;
        }
    } catch (e) {
        return null;
    }

    return null;
}

router.get("/auth/oidc/login", async (req, res) => {
    try {
        cleanupExpiredSessions();

        const config = await getOIDCConfig();
        if (!config.enabled) {
            throw createOIDCError("oidcDisabled", "OIDC is disabled");
        }

        const client = await getClient(config);
        const redirectURI = await resolveRedirectURI(req, config.redirectURI);

        const state = generators.state();
        const nonce = generators.nonce();
        const returnTo = validateReturnTo(req.query.returnTo);

        sessionStore.set(state, {
            nonce,
            redirectURI,
            createdAt: Date.now(),
            returnTo,
        });

        const authorizationUrl = client.authorizationUrl({
            scope: config.scope,
            redirect_uri: redirectURI,
            state,
            nonce,
        });

        res.redirect(authorizationUrl);
    } catch (error) {
        log.error("oidc", error);
        const errorCode = error.oidcCode || "oidcGenericError";
        res.redirect(`/oidc/callback?error=${encodeURIComponent(errorCode)}`);
    }
});

router.get("/auth/oidc/callback", async (req, res) => {
    let stateEntry;

    try {
        const config = await getOIDCConfig();
        if (!config.enabled) {
            throw createOIDCError("oidcDisabled", "OIDC is disabled");
        }

        const client = await getClient(config);
        const params = client.callbackParams(req);

        if (!params.state) {
            throw createOIDCError("oidcMissingState", "Missing state parameter in callback");
        }

        stateEntry = sessionStore.get(params.state);
        sessionStore.delete(params.state);

        if (!stateEntry) {
            throw createOIDCError("oidcInvalidState", "Invalid or expired state");
        }

        const tokenSet = await client.callback(stateEntry.redirectURI, params, {
            state: params.state,
            nonce: stateEntry.nonce,
        });

        const claims = tokenSet.claims();
        const usernameClaim = config.usernameClaim || "preferred_username";
        let username = claims?.[usernameClaim];

        if (!username && usernameClaim !== "preferred_username") {
            username = claims?.preferred_username;
        }

        if (!username) {
            username = claims?.email;
        }

        if (!username) {
            username = claims?.sub;
        }

        if (!username) {
            throw createOIDCError("oidcMissingUsername", "OIDC response does not include a usable username");
        }

        username = username.toString();

        let user = await findActiveUser(username);

        if (!user && config.autoCreateUser) {
            user = await createUser(username);
            log.info("oidc", `Created new user via OIDC: ${username}`);
        }

        if (!user) {
            throw createOIDCError("oidcUserNotAuthorized", "User not found and auto-create disabled");
        }

        const server = UptimeKumaServer.getInstance();
        const token = User.createJWT(user, server.jwtSecret);

        const redirectParams = new URLSearchParams();
        redirectParams.set("token", token);

        if (stateEntry.returnTo) {
            redirectParams.set("redirect", stateEntry.returnTo);
        }

        res.redirect(`/oidc/callback?${redirectParams.toString()}`);
    } catch (error) {
        log.error("oidc", error);
        const errorCode = error.oidcCode || "oidcGenericError";
        res.redirect(`/oidc/callback?error=${encodeURIComponent(errorCode)}`);
    }
});

router.get("/auth/oidc/info", async (_req, res) => {
    try {
        const config = await getOIDCConfig();
        res.json({
            ok: true,
            enabled: config.enabled,
            buttonLabel: config.buttonLabel || null,
        });
    } catch (error) {
        log.error("oidc", error);
        res.json({
            ok: false,
            error: error.oidcCode || "oidcGenericError",
        });
    }
});

module.exports = router;
