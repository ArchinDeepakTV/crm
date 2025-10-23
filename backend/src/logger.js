/**
 * Simple extensive logger utility for server-side usage.
 *
 * Features:
 * - Console logging with colors
 * - Optional file logging (daily files: yyyy-mm-dd.log)
 * - Log levels: error, warn, info, http, debug
 * - Request logging middleware that attaches `req.id` and logs request/response lifecycle
 * - Error logging middleware that logs stack traces and request context
 * - Basic log rotation cleanup by retention days (async)
 *
 * Configuration via environment variables:
 * - LOG_LEVEL: one of error|warn|info|http|debug (default: debug)
 * - LOG_TO_FILE: 'true'|'false' (default: true)
 * - LOG_DIR: directory for storing logs (default: ./logs)
 * - LOG_RETENTION_DAYS: integer days to keep log files (default: 14)
 *
 * Usage:
 * const logger = require('./logger');
 * app.use(logger.requestLogger);
 * app.use(logger.errorHandler); // as last error middleware
 * logger.info('server started');
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const DEFAULT_RETENTION_DAYS = 14;
const DEFAULT_LOG_DIR = path.join(process.cwd(), "logs");

const LEVELS = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

const COLORS = {
  error: "\x1b[31m", // red
  warn: "\x1b[33m", // yellow
  info: "\x1b[32m", // green
  http: "\x1b[36m", // cyan
  debug: "\x1b[35m", // magenta
  reset: "\x1b[0m",
};

const config = {
  level: process.env.LOG_LEVEL ? process.env.LOG_LEVEL.toLowerCase() : "debug",
  toFile:
    typeof process.env.LOG_TO_FILE !== "undefined"
      ? process.env.LOG_TO_FILE.toLowerCase() === "true"
      : true,
  dir: process.env.LOG_DIR || DEFAULT_LOG_DIR,
  retentionDays: parseInt(
    process.env.LOG_RETENTION_DAYS || DEFAULT_RETENTION_DAYS,
    10,
  ),
};

// ensure level is valid
if (!LEVELS.hasOwnProperty(config.level)) {
  config.level = "debug";
}

// ensure log dir exists if file logging enabled
if (config.toFile) {
  try {
    fs.mkdirSync(config.dir, { recursive: true });
  } catch (err) {
    // If creation fails, fallback to console-only and record error
    console.error(
      "Logger: failed to create log directory, falling back to console only",
      err,
    );
    config.toFile = false;
  }
}

// utility: generate short request id
function generateId() {
  return crypto.randomBytes(8).toString("hex");
}

// utility: timestamp ISO
function nowIso() {
  return new Date().toISOString();
}

// choose whether a level should be logged
function shouldLog(level) {
  const configured = LEVELS[config.level] || 0;
  const incoming = LEVELS[level] || 0;
  return incoming <= configured;
}

// sanitize headers for logging (remove sensitive ones)
function sanitizeHeaders(headers = {}) {
  const sanitized = { ...headers };
  const sensitive = ["authorization", "cookie", "set-cookie"];
  sensitive.forEach((h) => {
    Object.keys(sanitized).forEach((key) => {
      if (key.toLowerCase() === h) {
        sanitized[key] = "[REDACTED]";
      }
    });
  });
  return sanitized;
}

// format a single log line
function formatLine(level, message, meta = {}) {
  const ts = nowIso();
  const pid = process.pid;
  const levelStr = level.toUpperCase();
  const parts = [`${ts}`, `pid=${pid}`, levelStr, "-", message];

  // attach meta as JSON if present
  const metaKeys = Object.keys(meta);
  if (meta && metaKeys.length > 0) {
    try {
      parts.push(JSON.stringify(meta));
    } catch (err) {
      parts.push(String(meta));
    }
  }

  return parts.join(" ") + os.EOL;
}

// write to file (daily file)
function getLogFilePath() {
  const d = new Date();
  const date = d.toISOString().slice(0, 10); // YYYY-MM-DD
  const filename = `app-${date}.log`;
  return path.join(config.dir, filename);
}

function appendToFile(line) {
  if (!config.toFile) return;
  const filePath = getLogFilePath();
  // append asynchronously
  fs.appendFile(filePath, line, (err) => {
    if (err) {
      // fallback: print to console error but avoid infinite loop
      console.error("Logger: failed to write log to file", err);
    }
  });
}

// basic async cleanup of old log files
function cleanupOldLogs() {
  if (!config.toFile) return;
  const retentionMs = config.retentionDays * 24 * 60 * 60 * 1000;
  fs.readdir(config.dir, (err, files) => {
    if (err) {
      console.error("Logger: failed to read log dir for cleanup", err);
      return;
    }
    files.forEach((f) => {
      const full = path.join(config.dir, f);
      fs.stat(full, (errStat, stats) => {
        if (errStat) return;
        // only files
        if (!stats.isFile()) return;
        const age = Date.now() - stats.mtimeMs;
        if (age > retentionMs) {
          fs.unlink(full, (errUnlink) => {
            if (errUnlink) {
              console.error(
                "Logger: failed to delete old log file",
                full,
                errUnlink,
              );
            } else {
              console.info("Logger: deleted old log file", full);
            }
          });
        }
      });
    });
  });
}

// run cleanup in background on startup (non-blocking)
setImmediate(() => {
  try {
    cleanupOldLogs();
  } catch (err) {
    // don't crash the process due to logger cleanup
    console.error("Logger: cleanup failed", err);
  }
});

// low-level log emitter
function emit(level, message, meta = {}) {
  const line = formatLine(level, message, meta);

  // console output with colors
  const color = COLORS[level] || COLORS.reset;
  const reset = COLORS.reset;
  try {
    // Print leveled console messages: error->console.error, warn->console.warn otherwise -> console.log
    const consoleOutput = `${color}${line.trim()}${reset}`;
    if (level === "error") {
      console.error(consoleOutput);
    } else if (level === "warn") {
      console.warn(consoleOutput);
    } else {
      console.log(consoleOutput);
    }
  } catch (err) {
    // swallow console errors
  }

  // file output
  try {
    appendToFile(line);
  } catch (err) {
    // swallow file errors
  }
}

// exported level functions that check config
const logger = {
  setLevel(newLevel) {
    if (LEVELS.hasOwnProperty(newLevel)) {
      config.level = newLevel;
      this.info(`Log level set to ${newLevel}`);
    } else {
      this.warn(`Attempt to set invalid log level: ${newLevel}`);
    }
  },

  debug(msg, meta) {
    if (!shouldLog("debug")) return;
    emit("debug", String(msg), meta);
  },

  info(msg, meta) {
    if (!shouldLog("info")) return;
    emit("info", String(msg), meta);
  },

  http(msg, meta) {
    if (!shouldLog("http")) return;
    emit("http", String(msg), meta);
  },

  warn(msg, meta) {
    if (!shouldLog("warn")) return;
    emit("warn", String(msg), meta);
  },

  error(msg, meta) {
    if (!shouldLog("error")) return;
    emit("error", String(msg), meta);
  },

  // Express-compatible request logger middleware
  requestLogger(opts = {}) {
    // opts: { skipPaths: [/health/], logHeaders: boolean, logBody: boolean, maxBodySize: number }
    const skipPaths = opts.skipPaths || [];
    const logHeaders =
      typeof opts.logHeaders === "boolean" ? opts.logHeaders : true;
    const logBody = typeof opts.logBody === "boolean" ? opts.logBody : true;
    const maxBodySize =
      typeof opts.maxBodySize === "number" ? opts.maxBodySize : 10 * 1024; // 10KB default

    // keys to redact from bodies (case-insensitive)
    const REDACT_KEYS = opts.redactKeys || [
      "password",
      "pass",
      "pwd",
      "token",
      "authorization",
      "auth",
      "cookie",
      "set-cookie",
      "creditCard",
      "cc",
      "ssn",
    ];

    function redactObject(obj) {
      if (obj == null) return obj;
      if (typeof obj !== "object") return obj;
      // avoid modifying original
      if (Array.isArray(obj)) {
        return obj.map((v) =>
          typeof v === "object" ? redactObject(v) : redactValue("", v),
        );
      }
      const out = {};
      for (const [k, v] of Object.entries(obj)) {
        const lower = k.toLowerCase();
        const shouldRedact = REDACT_KEYS.some((rk) =>
          lower.includes(rk.toLowerCase()),
        );
        if (shouldRedact) {
          out[k] = "[REDACTED]";
        } else if (typeof v === "object" && v !== null) {
          out[k] = redactObject(v);
        } else {
          out[k] = redactValue(k, v);
        }
      }
      return out;
    }

    function redactValue(key, value) {
      try {
        if (value == null) return value;
        // if value looks like a long token/credit, redact partially
        if (typeof value === "string") {
          const trimmed = value.trim();
          if (trimmed.length > 512) {
            return `[TRUNCATED ${trimmed.length} chars]`;
          }
          return trimmed;
        }
        return value;
      } catch (e) {
        return "[REDACTED]";
      }
    }

    function safeStringify(obj, limit) {
      try {
        const s = typeof obj === "string" ? obj : JSON.stringify(obj);
        if (typeof s !== "string") return String(s).slice(0, limit);
        if (s.length > limit)
          return s.slice(0, limit) + `...[TRUNCATED ${s.length} bytes]`;
        return s;
      } catch (err) {
        return "[UNSERIALIZABLE]";
      }
    }

    return function (req, res, next) {
      try {
        const start = process.hrtime.bigint();
        // attach id if not present
        if (!req.id) req.id = generateId();

        // check skip
        for (const sp of skipPaths) {
          if (sp instanceof RegExp ? sp.test(req.url) : req.url.includes(sp)) {
            return next();
          }
        }

        const safeHeaders = logHeaders
          ? sanitizeHeaders(req.headers)
          : undefined;

        // Prepare request body (if available). Only include when logBody true.
        let requestBodyPreview;
        if (logBody) {
          try {
            // many apps populate req.body via bodyParser before this middleware
            const rawBody = req.body !== undefined ? req.body : undefined;
            const redacted =
              rawBody !== undefined ? redactObject(rawBody) : undefined;
            requestBodyPreview =
              redacted !== undefined
                ? safeStringify(redacted, maxBodySize)
                : undefined;
          } catch (e) {
            requestBodyPreview = "[ERROR_READING_BODY]";
          }
        }

        const reqMeta = {
          id: req.id,
          method: req.method,
          url: req.originalUrl || req.url,
          ip: req.ip || (req.connection && req.connection.remoteAddress),
        };
        if (logHeaders) reqMeta.headers = safeHeaders;
        if (logBody) reqMeta.body = requestBodyPreview;

        // initial request log with more details
        logger.http("incoming request", reqMeta);

        // Capture response body by patching write/end
        let chunks = [];
        const originalWrite = res.write;
        const originalEnd = res.end;
        let responseBodyPreview;

        // patch write
        res.write = function (chunk, encoding, callback) {
          try {
            if (chunk) {
              // chunk might be string or Buffer
              if (Buffer.isBuffer(chunk)) {
                chunks.push(chunk);
              } else if (typeof chunk === "string") {
                chunks.push(Buffer.from(chunk, encoding));
              }
              // avoid memory explosion: cap captured size
              const total = chunks.reduce((acc, c) => acc + c.length, 0);
              if (total > maxBodySize) {
                // if too big, truncate stored chunks to the limit
                const buf = Buffer.concat(chunks);
                chunks = [buf.slice(0, maxBodySize)];
              }
            }
          } catch (e) {
            // ignore capture errors
          }
          return originalWrite.apply(res, arguments);
        };

        // patch end
        res.end = function (chunk, encoding, callback) {
          try {
            if (chunk) {
              if (Buffer.isBuffer(chunk)) {
                chunks.push(chunk);
              } else if (typeof chunk === "string") {
                chunks.push(Buffer.from(chunk, encoding));
              }
            }
          } catch (e) {
            // ignore capture errors
          }
          // call original end
          const result = originalEnd.apply(res, arguments);
          return result;
        };

        // on finish log status, duration and response body (sanitized/truncated)
        res.on("finish", () => {
          try {
            const end = process.hrtime.bigint();
            const durationMs = Number(end - start) / 1e6;
            let responseText;
            if (chunks.length > 0) {
              try {
                const buf = Buffer.concat(chunks);
                const text = buf.toString("utf8");
                // attempt JSON parse & redact if possible
                let parsed;
                try {
                  parsed = JSON.parse(text);
                  parsed = redactObject(parsed);
                  responseText = safeStringify(parsed, maxBodySize);
                } catch (e) {
                  responseText =
                    text.length > maxBodySize
                      ? text.slice(0, maxBodySize) +
                        `...[TRUNCATED ${text.length} bytes]`
                      : text;
                }
              } catch (e) {
                responseText = "[UNREADABLE_RESPONSE_BODY]";
              }
            }

            responseBodyPreview = responseText;

            const resMeta = {
              id: req.id,
              method: req.method,
              url: req.originalUrl || req.url,
              statusCode: res.statusCode,
              durationMs: Math.round(durationMs * 100) / 100,
            };
            if (logHeaders)
              resMeta.headers = sanitizeHeaders(
                res.getHeaders ? res.getHeaders() : {},
              );
            if (logBody && typeof responseBodyPreview !== "undefined")
              resMeta.body = responseBodyPreview;

            logger.http("request completed", resMeta);

            // free memory
            chunks = null;
          } catch (e) {
            logger.error("failed to log finished request", {
              id: req.id,
              err: e && e.message ? e.message : String(e),
            });
          }
        });

        // on error for the response stream
        res.on("error", (err) => {
          logger.error("response error", {
            id: req.id,
            err: err && err.message ? err.message : String(err),
          });
        });

        next();
      } catch (err) {
        // don't crash the app if logger middleware fails
        console.error("Logger.requestLogger middleware error", err);
        next();
      }
    };
  },

  // Express-compatible error handler - should be used as last error handling middleware.
  // Usage: app.use(logger.errorHandler);
  errorHandler(err, req, res, next) {
    try {
      const id = (req && req.id) || generateId();
      const meta = {
        id,
        message: err && err.message ? err.message : String(err),
        stack: err && err.stack ? err.stack : undefined,
        method: req && req.method,
        url: req && (req.originalUrl || req.url),
        ip: req && (req.ip || (req.connection && req.connection.remoteAddress)),
      };
      logger.error("unhandled error", meta);
    } catch (e) {
      // swallow
      console.error("Logger.errorHandler failed", e);
    }
    // Delegate to next error handler (so existing behavior is preserved).
    if (typeof next === "function") {
      next(err);
    } else if (res && !res.headersSent) {
      // last resort: respond with 500
      try {
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error" });
      } catch (e) {
        // nothing else we can do
      }
    }
  },
};

module.exports = logger;
