const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const logger = require("./logger");
const { MongoClient } = require("mongodb");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const Redis = require("ioredis");

// Redis connection (used for sessions & blacklist). Use REDIS_URL env or default localhost.
const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";
const redis = new Redis(REDIS_URL);

// Redis helper utilities
async function redisSetSession(jti, data, ttlMs = 30 * 24 * 60 * 60 * 1000) {
  // store as hash, and set TTL
  const key = `session:${jti}`;
  const flat = {};
  Object.keys(data).forEach((k) => {
    flat[k] = typeof data[k] === "string" ? data[k] : JSON.stringify(data[k]);
  });
  await redis.hset(key, flat);
  await redis.pexpire(key, ttlMs);
}

async function redisGetSession(jti) {
  const key = `session:${jti}`;
  const exists = await redis.exists(key);
  if (!exists) return null;
  const data = await redis.hgetall(key);
  // normalize fields we expect
  if (!data) return null;
  try {
    if (data.lastActivity) data.lastActivity = parseInt(data.lastActivity, 10);
  } catch (e) {}
  return data;
}

async function redisInvalidateSession(jti) {
  const key = `session:${jti}`;
  await redis.del(key);
  // add to redis blacklist for quick denial; set TTL to a reasonable retention (e.g., 30 days)
  const blKey = `blacklist:${jti}`;
  await redis.set(
    blKey,
    "1",
    "PX",
    parseInt(
      process.env.BLACKLIST_RETENTION_MS || String(30 * 24 * 60 * 60 * 1000),
      10,
    ),
  );
}

async function redisIsBlacklisted(jti) {
  if (!jti) return false;
  const blKey = `blacklist:${jti}`;
  const v = await redis.get(blKey);
  return !!v;
}

// JWT configuration and session management
// - JWT_SECRET_LIST: comma-separated list (or JSON array) of secrets for rotation. The first secret is used to sign new tokens.
// - JWT_EXPIRES_IN still respected for backward-compat, but sessions enforce inactivity server-side.
// - SESSION_INACTIVITY_MINUTES controls inactivity timeout (default 5 minutes).
const JWT_SECRET_LIST_RAW =
  process.env.JWT_SECRET_LIST ||
  process.env.JWT_SECRET ||
  "please-change-this-secret";
let JWT_SECRETS = [];
try {
  // allow either JSON array or comma-separated string
  if (JWT_SECRET_LIST_RAW.trim().startsWith("[")) {
    JWT_SECRETS = JSON.parse(JWT_SECRET_LIST_RAW);
  } else {
    JWT_SECRETS = JWT_SECRET_LIST_RAW.split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
} catch (e) {
  JWT_SECRETS = [String(JWT_SECRET_LIST_RAW)];
}
if (!Array.isArray(JWT_SECRETS) || JWT_SECRETS.length === 0) {
  JWT_SECRETS = [String(JWT_SECRET_LIST_RAW)];
}
const CURRENT_JWT_SECRET = JWT_SECRETS[0];
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";
const SESSION_INACTIVITY_MINUTES = parseInt(
  process.env.SESSION_INACTIVITY_MINUTES || "5",
  10,
);
const INACTIVITY_MS = SESSION_INACTIVITY_MINUTES * 60 * 1000;
const JWT_COOKIE = (process.env.JWT_COOKIE || "true").toLowerCase() === "true"; // default to true - cookie-based
const JWT_COOKIE_NAME = process.env.JWT_COOKIE_NAME || "session_token";

const router = express.Router();

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017";
const MONGO_DB = process.env.MONGO_DB || "v01";
const MONGO_USERS_COLLECTION = process.env.MONGO_USERS_COLLECTION || "users";

// Argon2 options (tunable via env)
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  timeCost: parseInt(process.env.ARGON2_TIME || "3", 10), // iterations
  memoryCost: parseInt(process.env.ARGON2_MEMORY || `${1 << 16}`, 10), // KB (default 64MiB)
  parallelism: parseInt(process.env.ARGON2_PARALLELISM || "1", 10),
};

/**
 * Mongo connection helper (lazy)
 */
let mongoClient = null;
let usersCollection = null;
async function connectMongo() {
  if (usersCollection) return usersCollection;
  if (!mongoClient) {
    mongoClient = new MongoClient(MONGO_URI);
  }
  await mongoClient.connect();
  const db = mongoClient.db(MONGO_DB);
  usersCollection = db.collection(MONGO_USERS_COLLECTION);

  // Ensure a unique index on username to prevent duplicates/race conditions.
  try {
    await usersCollection.createIndex(
      { username: 1 },
      { unique: true, background: true },
    );
    logger.info("Ensured unique index on users.username");
  } catch (idxErr) {
    // If index creation fails (permissions, existing conflicting data), log a warning but continue.
    logger.warn("Could not create unique index on users.username", {
      err: idxErr && idxErr.message ? idxErr.message : String(idxErr),
    });
  }

  logger.info(
    `MongoDB connected to ${MONGO_URI}, db=${MONGO_DB}, collection=${MONGO_USERS_COLLECTION}`,
  );
  return usersCollection;
}

/**
 * Private key loading
 */
const privateKeyPath =
  process.env.PRIVATE_KEY_PATH || path.join(process.cwd(), "private.pem");

let privateKey = null;
try {
  privateKey = fs.readFileSync(privateKeyPath, "utf8");
  logger.info(`Private key loaded from ${privateKeyPath}`);
} catch (err) {
  logger.warn(
    `Private key not found at ${privateKeyPath}. Decryption endpoints will return 500 until a key is provided.`,
  );
}

/**
 * Decrypt base64 RSA-OAEP (sha256) ciphertext
 */
function decryptPassword(encryptedBase64) {
  if (!privateKey) {
    throw new Error("Private key not loaded");
  }
  const buffer = Buffer.from(encryptedBase64, "base64");
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    buffer,
  );
  return decrypted.toString("utf8");
}

/**
 * Username validation (strict)
 * - 3..30 chars
 * - letters, numbers, dot, underscore, hyphen
 * - cannot start/end with . _ -
 * - no consecutive dots
 */
function isValidUsername(u) {
  if (!u || typeof u !== "string") return false;
  const s = u.trim();
  if (s.length < 3 || s.length > 30) return false;
  if (
    [".", "-", "_"].includes(s[0]) ||
    [".", "-", "_"].includes(s[s.length - 1])
  )
    return false;
  if (s.includes("..")) return false;
  const re = /^[A-Za-z0-9._-]+$/;
  return re.test(s);
}

/**
 * JWT auth middleware
 * - Expects Authorization: Bearer <token>
 * - Attaches decoded payload to req.user
 */
function authMiddleware(req, res, next) {
  const header = req.headers["authorization"] || req.headers["Authorization"];
  if (!header)
    return res
      .status(401)
      .json({ success: false, message: "Missing Authorization header" });
  const parts = header.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer")
    return res
      .status(401)
      .json({ success: false, message: "Invalid Authorization header" });
  const token = parts[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (err) {
    logger.warn("JWT verification failed", {
      err: err && err.message ? err.message : String(err),
    });
    return res
      .status(401)
      .json({ success: false, message: "Invalid or expired token" });
  }
}

/**
 * POST /register
 * Body: { username, password } where password is base64 ciphertext
 */
router.post("/register", async (req, res) => {
  if (!privateKey) {
    logger.error("Attempt to call /register but private key not available", {
      ip: req.ip,
      path: req.path,
    });
    return res
      .status(500)
      .json({ success: false, message: "Server private key not available" });
  }

  const encryptedPwd = req.body && req.body.password;
  const username = req.body && req.body.username;

  if (!username)
    return res
      .status(400)
      .json({ success: false, message: "Missing username" });
  if (!isValidUsername(username)) {
    return res.status(422).json({
      success: false,
      message:
        "Invalid username format (3-30 chars, letters/numbers/._-; cannot start/end with ._-)",
    });
  }
  if (!encryptedPwd)
    return res
      .status(400)
      .json({ success: false, message: "Missing password" });

  try {
    // decrypt
    const password = decryptPassword(encryptedPwd);

    // dev-only plaintext logging
    if (
      process.env.LOG_DECRYPTED &&
      process.env.LOG_DECRYPTED.toLowerCase() === "true"
    ) {
      /* eslint-disable no-console */
      console.log(
        `DECRYPTED_PASSWORD register user=${username} id=${req.id || "N/A"} ip=${req.ip || "N/A"}: ${password}`,
      );
      /* eslint-enable no-console */
    }

    // connect db
    try {
      await connectMongo();
    } catch (dbConnErr) {
      logger.error("Failed to connect to MongoDB", {
        err:
          dbConnErr && dbConnErr.message
            ? dbConnErr.message
            : String(dbConnErr),
      });
      return res
        .status(500)
        .json({ success: false, message: "Database connection failed" });
    }

    // check existing
    const existing = await usersCollection.findOne({ username });
    if (existing) {
      return res
        .status(409)
        .json({ success: false, message: "Username already taken" });
    }

    // hash with argon2
    let hashed;
    try {
      hashed = await argon2.hash(password, ARGON2_OPTIONS);
    } catch (hashErr) {
      logger.error("Argon2 hashing failed", {
        err: hashErr && hashErr.message ? hashErr.message : String(hashErr),
        username,
      });
      return res
        .status(500)
        .json({ success: false, message: "Password hashing failed" });
    }

    // insert user
    try {
      const now = new Date();
      const userDoc = {
        username,
        passwordHash: hashed,
        createdAt: now,
        updatedAt: now,
      };
      await usersCollection.insertOne(userDoc);
      logger.info("User registered", { username, id: req.id, ip: req.ip });
      return res.status(201).json({ success: true });
    } catch (dbErr) {
      logger.error("Failed to insert user in MongoDB", {
        err: dbErr && dbErr.message ? dbErr.message : String(dbErr),
        username,
      });
      return res
        .status(500)
        .json({ success: false, message: "Failed to store user" });
    }
  } catch (err) {
    logger.error("Registration failed", {
      err: err && err.message ? err.message : String(err),
      id: req.id,
      ip: req.ip,
    });
    return res.status(400).json({
      success: false,
      message: "Invalid encrypted payload or decryption failed",
    });
  }
});

/**
 * POST /login
 * Body: { username, password } where password is base64 ciphertext
 * This endpoint verifies credentials (does NOT create users).
 */
router.post("/login", async (req, res) => {
  if (!privateKey) {
    logger.error("Attempt to call /login but private key not available", {
      ip: req.ip,
      path: req.path,
    });
    return res
      .status(500)
      .json({ success: false, message: "Server private key not available" });
  }

  const encryptedPwd = req.body && req.body.password;
  const username = req.body && req.body.username;

  if (!encryptedPwd || !username)
    return res
      .status(400)
      .json({ success: false, message: "Missing username or password" });
  if (!isValidUsername(username))
    return res
      .status(422)
      .json({ success: false, message: "Invalid username" });

  try {
    const password = decryptPassword(encryptedPwd);

    // dev-only plaintext logging
    if (
      process.env.LOG_DECRYPTED &&
      process.env.LOG_DECRYPTED.toLowerCase() === "true"
    ) {
      /* eslint-disable no-console */
      console.log(
        `DECRYPTED_PASSWORD login user=${username} id=${req.id || "N/A"} ip=${req.ip || "N/A"}: ${password}`,
      );
      /* eslint-enable no-console */
    }

    logger.info(`Login attempt for user ${username}`, {
      id: req.id,
      ip: req.ip,
    });

    // ensure db
    try {
      await connectMongo();
    } catch (dbConnErr) {
      logger.error("Failed to connect to MongoDB", {
        err:
          dbConnErr && dbConnErr.message
            ? dbConnErr.message
            : String(dbConnErr),
      });
      return res
        .status(500)
        .json({ success: false, message: "Database connection failed" });
    }

    // find user
    const user = await usersCollection.findOne({ username });
    if (!user || !user.passwordHash) {
      logger.warn("Authentication failed (user not found)", {
        username,
        id: req.id,
      });
      // generic message to avoid user enumeration
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    // verify argon2
    let ok = false;
    try {
      ok = await argon2.verify(user.passwordHash, password);
    } catch (verifyErr) {
      logger.error("Argon2 verify error", {
        err:
          verifyErr && verifyErr.message
            ? verifyErr.message
            : String(verifyErr),
        username,
        id: req.id,
      });
      return res
        .status(500)
        .json({ success: false, message: "Authentication failed" });
    }

    if (!ok) {
      logger.warn("Authentication failed (invalid password)", {
        username,
        id: req.id,
      });
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    // Create a session entry and issue a JWT that includes `sub` and `jti`
    try {
      // generate a jti for this session (use crypto.randomUUID if available)
      const jti =
        (crypto.randomUUID && crypto.randomUUID()) ||
        crypto.randomBytes(16).toString("hex");
      const payload = {
        sub: String(user._id),
        username,
        jti,
      };

      // Sign with the current secret
      const token = jwt.sign(payload, CURRENT_JWT_SECRET, {
        // No short expiry required because we enforce inactivity server-side.
        // Still include an expiresIn to have an ultimate fallback if desired (kept configurable).
        expiresIn: JWT_EXPIRES_IN,
      });

      // Persist session record in Redis (primary runtime) and also store an audit record in Mongo (best-effort).
      try {
        // primary: store session in Redis with the inactivity window as TTL
        const sessionData = {
          jti,
          userId: String(user._id),
          username,
          lastActivity: Date.now(),
          valid: "1",
        };
        // set session TTL in Redis: use SESSION_INACTIVITY_MINUTES or configured long duration
        const redisTtlMs = parseInt(
          process.env.REDIS_SESSION_TTL_MS || String(30 * 24 * 60 * 60 * 1000),
          10,
        );
        await redisSetSession(
          jti,
          { ...sessionData, lastActivity: String(sessionData.lastActivity) },
          redisTtlMs,
        );

        // best-effort: also record session in Mongo for audits and to support systems without Redis
        try {
          await connectMongo();
          const db = mongoClient.db(MONGO_DB);
          const sessions = db.collection("sessions");
          await sessions.updateOne(
            { jti },
            {
              $set: {
                jti,
                userId: String(user._id),
                lastActivity: new Date(),
                valid: true,
                createdAt: new Date(),
              },
            },
            { upsert: true },
          );
          logger.info("Session created (Mongo audit) and stored in Redis", {
            username,
            jti,
            id: req.id,
          });
        } catch (auditErr) {
          logger.warn(
            "Failed to create Mongo audit record for session; session still stored in Redis",
            {
              err:
                auditErr && auditErr.message
                  ? auditErr.message
                  : String(auditErr),
              jti,
            },
          );
        }
      } catch (sessionErr) {
        logger.error("Failed to create session in Redis", {
          err:
            sessionErr && sessionErr.message
              ? sessionErr.message
              : String(sessionErr),
          username,
        });
        // proceed anyway — token exists, but auth will fail if Redis is unavailable
      }

      // Set HttpOnly cookie if configured
      if (JWT_COOKIE) {
        const cookieOpts = {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "lax",
          // Cookie longevity is not used to enforce inactivity; server-side session controls logout.
          maxAge: parseInt(
            process.env.JWT_COOKIE_MAX_AGE || String(30 * 24 * 60 * 60 * 1000),
            10,
          ), // default 30 days
        };
        res.cookie(JWT_COOKIE_NAME, token, cookieOpts);
        logger.debug("Session cookie set", { username, jti });
        return res.json({ success: true });
      }

      // fallback: return token in JSON (not recommended for production)
      logger.info("Authentication successful", {
        username,
        id: req.id,
        ip: req.ip,
      });
      return res.json({ success: true, token });
    } catch (tokenErr) {
      logger.error("Failed to sign JWT", {
        err: tokenErr && tokenErr.message ? tokenErr.message : String(tokenErr),
        username,
        id: req.id,
      });
      return res
        .status(500)
        .json({ success: false, message: "Failed to create session token" });
    }
  } catch (err) {
    logger.error("Decryption/Authentication failed for /login", {
      err: err && err.message ? err.message : String(err),
      id: req.id,
      ip: req.ip,
    });
    return res.status(400).json({
      success: false,
      message: "Invalid encrypted payload or decryption failed",
    });
  }
});

/**
 * Logout endpoint
 * - Invalidates the server-side session and blacklists the jti so token cannot be used again.
 * - Accepts token via cookie or Authorization header.
 */
router.post("/logout", async (req, res) => {
  try {
    // retrieve token from cookie or header
    let token = null;
    if (req.cookies && req.cookies[JWT_COOKIE_NAME])
      token = req.cookies[JWT_COOKIE_NAME];
    const header = req.headers["authorization"] || req.headers["Authorization"];
    if (!token && header) {
      const parts = header.split(" ");
      if (parts.length === 2 && parts[0] === "Bearer") token = parts[1];
    }
    if (!token)
      return res
        .status(400)
        .json({ success: false, message: "No session token provided" });

    // Try to decode token using any of the known secrets to obtain jti
    let decoded = null;
    for (const s of JWT_SECRETS) {
      try {
        decoded = jwt.verify(token, s);
        break;
      } catch (e) {
        // try next secret
      }
    }
    if (!decoded || !decoded.jti) {
      // Clear cookie if present
      if (JWT_COOKIE && req.cookies && req.cookies[JWT_COOKIE_NAME]) {
        res.clearCookie(JWT_COOKIE_NAME, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "lax",
        });
      }
      return res
        .status(400)
        .json({ success: false, message: "Invalid session token" });
    }

    const jti = decoded.jti;
    try {
      await connectMongo();
      const db = mongoClient.db(MONGO_DB);
      const sessions = db.collection("sessions");
      const blacklist = db.collection("token_blacklist");

      // Invalidate session in Redis and add to Redis-backed blacklist (fast path),
      // then also persist invalidation in Mongo (best-effort).
      try {
        await redisInvalidateSession(jti);
      } catch (redisErr) {
        logger.warn("Redis session invalidation failed during logout", {
          err:
            redisErr && redisErr.message ? redisErr.message : String(redisErr),
          jti,
        });
      }

      try {
        // persist invalidation in Mongo for audit: mark session invalid and add blacklist record
        await sessions.updateOne(
          { jti },
          { $set: { valid: false, invalidatedAt: new Date() } },
        );
        await blacklist.updateOne(
          { jti },
          { $set: { jti, invalidatedAt: new Date() } },
          { upsert: true },
        );
      } catch (mongoErr) {
        logger.warn("Mongo session invalidation/audit failed during logout", {
          err:
            mongoErr && mongoErr.message ? mongoErr.message : String(mongoErr),
          jti,
        });
      }
    } catch (e) {
      logger.error("Failed to invalidate session during logout", {
        err: e && e.message ? e.message : String(e),
      });
      // continue to clear cookie client-side
    }

    if (JWT_COOKIE) {
      res.clearCookie(JWT_COOKIE_NAME, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
      });
    }
    return res.json({ success: true });
  } catch (e) {
    logger.error("Logout failed", {
      err: e && e.message ? e.message : String(e),
    });
    return res.status(500).json({ success: false, message: "Logout failed" });
  }
});

/**
 * Protected route that returns basic info about the authenticated user.
 * Example usage: GET /me with Authorization: Bearer <token> or cookie.
 */
router.get("/me", async (req, res) => {
  try {
    // Attempt to authenticate via cookie or Authorization header
    // Reuse the auth behavior used for middleware but inline here to access token info
    let token = null;
    if (req.cookies && req.cookies[JWT_COOKIE_NAME])
      token = req.cookies[JWT_COOKIE_NAME];
    const header = req.headers["authorization"] || req.headers["Authorization"];
    if (!token && header) {
      const parts = header.split(" ");
      if (parts.length === 2 && parts[0] === "Bearer") token = parts[1];
    }
    if (!token)
      return res.status(401).json({ success: false, message: "Missing token" });

    // verify token against rotating secrets and extract jti/sub
    let decoded = null;
    for (const s of JWT_SECRETS) {
      try {
        decoded = jwt.verify(token, s);
        break;
      } catch (e) {
        // try next
      }
    }
    if (!decoded || !decoded.jti || !decoded.sub)
      return res.status(401).json({ success: false, message: "Invalid token" });

    // Check blacklist and session activity using Redis (fast path). Fall back to Mongo if Redis is unavailable.
    try {
      // quick Redis check
      const blacklisted = await redisIsBlacklisted(decoded.jti);
      if (blacklisted) {
        if (JWT_COOKIE)
          res.clearCookie(JWT_COOKIE_NAME, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
          });
        return res
          .status(401)
          .json({ success: false, message: "Token invalidated" });
      }

      // get session from Redis
      const sess = await redisGetSession(decoded.jti);
      if (!sess || !sess.valid) {
        // fallback to Mongo check
        try {
          await connectMongo();
          const db = mongoClient.db(MONGO_DB);
          const sessionsColl = db.collection("sessions");
          const msession = await sessionsColl.findOne({
            jti: decoded.jti,
            valid: true,
          });
          if (!msession) {
            if (JWT_COOKIE)
              res.clearCookie(JWT_COOKIE_NAME, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "lax",
              });
            return res.status(401).json({
              success: false,
              message: "Session not found or invalid",
            });
          }
          // if Mongo session exists, seed Redis for faster future checks
          await redisSetSession(decoded.jti, {
            jti: msession.jti,
            userId: msession.userId,
            username: msession.username || "",
            lastActivity: String(
              msession.lastActivity
                ? new Date(msession.lastActivity).getTime()
                : Date.now(),
            ),
            valid: "1",
          });
        } catch (mongoFallbackErr) {
          logger.warn("Redis session missing and Mongo fallback failed", {
            err:
              mongoFallbackErr && mongoFallbackErr.message
                ? mongoFallbackErr.message
                : String(mongoFallbackErr),
          });
          return res
            .status(401)
            .json({ success: false, message: "Session not found or invalid" });
        }
      } else {
        // we have redis session; check inactivity
        const lastActivity = parseInt(
          sess.lastActivity || String(Date.now()),
          10,
        );
        if (Date.now() - lastActivity > INACTIVITY_MS) {
          // expired due to inactivity: invalidate in Redis and record in Mongo/blacklist
          try {
            await redisInvalidateSession(decoded.jti);
            // best-effort: persist invalidation in Mongo
            try {
              await connectMongo();
              const db = mongoClient.db(MONGO_DB);
              const sessionsColl = db.collection("sessions");
              const blacklistColl = db.collection("token_blacklist");
              await sessionsColl.updateOne(
                { jti: decoded.jti },
                { $set: { valid: false, invalidatedAt: new Date() } },
              );
              await blacklistColl.updateOne(
                { jti: decoded.jti },
                { $set: { jti: decoded.jti, invalidatedAt: new Date() } },
                { upsert: true },
              );
            } catch (e) {
              logger.warn(
                "Failed to persist inactivity invalidation to Mongo",
                { err: e && e.message ? e.message : String(e) },
              );
            }
          } catch (e) {
            logger.warn("Failed to invalidate redis session on inactivity", {
              err: e && e.message ? e.message : String(e),
            });
          }
          if (JWT_COOKIE)
            res.clearCookie(JWT_COOKIE_NAME, {
              httpOnly: true,
              secure: process.env.NODE_ENV === "production",
              sameSite: "lax",
            });
          return res.status(401).json({
            success: false,
            message: "Session expired due to inactivity",
          });
        }

        // Sliding window: update lastActivity in Redis and extend TTL
        try {
          await redis.hset(
            `session:${decoded.jti}`,
            "lastActivity",
            String(Date.now()),
          );
          // Optionally extend TTL; set to configured session TTL (in ms)
          const redisTtlMs = parseInt(
            process.env.REDIS_SESSION_TTL_MS ||
              String(30 * 24 * 60 * 60 * 1000),
            10,
          );
          await redis.pexpire(`session:${decoded.jti}`, redisTtlMs);
        } catch (e) {
          logger.warn("Failed to refresh session lastActivity in Redis", {
            err: e && e.message ? e.message : String(e),
          });
        }
      }
    } catch (redisCheckErr) {
      // On Redis error, fall back to Mongo-only approach
      logger.warn(
        "Redis check failed while validating session; falling back to Mongo",
        {
          err:
            redisCheckErr && redisCheckErr.message
              ? redisCheckErr.message
              : String(redisCheckErr),
        },
      );
      await connectMongo();
      const db = mongoClient.db(MONGO_DB);
      const blacklist = db.collection("token_blacklist");
      const bl = await blacklist.findOne({ jti: decoded.jti });
      if (bl)
        return res
          .status(401)
          .json({ success: false, message: "Token invalidated" });

      const sessions = db.collection("sessions");
      const session = await sessions.findOne({ jti: decoded.jti, valid: true });
      if (!session)
        return res
          .status(401)
          .json({ success: false, message: "Session not found or invalid" });
      const last = session.lastActivity || session.createdAt;
      if (Date.now() - new Date(last).getTime() > INACTIVITY_MS) {
        await sessions.updateOne(
          { jti: decoded.jti },
          { $set: { valid: false, invalidatedAt: new Date() } },
        );
        await blacklist.updateOne(
          { jti: decoded.jti },
          { $set: { jti: decoded.jti, invalidatedAt: new Date() } },
          { upsert: true },
        );
        if (JWT_COOKIE)
          res.clearCookie(JWT_COOKIE_NAME, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
          });
        return res.status(401).json({
          success: false,
          message: "Session expired due to inactivity",
        });
      }
      // update lastActivity in Mongo as fallback
      await sessions.updateOne(
        { jti: decoded.jti },
        { $set: { lastActivity: new Date() } },
      );
    }

    // Fetch user info
    const users = db.collection(MONGO_USERS_COLLECTION);
    const user = await users.findOne(
      { _id: new (require("mongodb").ObjectId)(decoded.sub) },
      { projection: { passwordHash: 0 } },
    );
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    return res.json({
      success: true,
      user: {
        sub: decoded.sub,
        username: user.username,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    });
  } catch (e) {
    logger.error("Failed to serve /me", {
      err: e && e.message ? e.message : String(e),
    });
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

module.exports = router;

/**
 * Protected route that returns basic info about the authenticated user.
 * Example usage: GET /me with Authorization: Bearer <token>
 */
router.get("/me", authMiddleware, async (req, res) => {
  try {
    // Ensure DB connection (so we can fetch user metadata)
    await connectMongo();
    const username = req.user && req.user.username;
    if (!username)
      return res
        .status(401)
        .json({ success: false, message: "Invalid session" });

    const user = await usersCollection.findOne(
      { username },
      { projection: { passwordHash: 0 } },
    );
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Return non-sensitive user info
    return res.json({
      success: true,
      user: {
        username: user.username,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    });
  } catch (e) {
    logger.error("Failed to serve /me", {
      err: e && e.message ? e.message : String(e),
    });
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

module.exports = router;
