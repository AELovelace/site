const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { promisify } = require("util");
const { DatabaseSync } = require("node:sqlite");
const { URL } = require("url");

const PORT = Number(process.env.PORT) || 3000;
const APP_ROOT = path.join(__dirname, "engine");
const DATA_ROOT = path.join(__dirname, "data");
const USERS_DB_PATH = path.join(DATA_ROOT, "users.db");
const CHAT_DB_PATH = path.join(DATA_ROOT, "chat.db");
const LOG_PATH = path.join(APP_ROOT, "log.html");
const IMAGI_ROOT = path.join(APP_ROOT, "imagi");
const UIMG_ROOT = path.join(APP_ROOT, "uimg");

const sessions = new Map();
const streamClients = new Set();
let userDatabase;
let chatDatabase;
const scryptAsync = promisify(crypto.scrypt);
const USERNAME_REGEX = /^[A-Za-z0-9_-]{1,32}$/;
const LEGACY_HISTORY_NOTICE = "Legacy chat history was imported from the old HTML log and is hidden for safety.";

const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".gif": "image/gif",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".mp4": "video/mp4",
  ".php": "text/html; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".wav": "audio/wav",
  ".woff": "font/woff",
  ".zip": "application/zip",
};

function shouldUseSecureCookies(request) {
  const forwardedProto = (request.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  return forwardedProto === "https" || request.socket.encrypted === true;
}

function buildCookie(name, value, request, overrides = {}) {
  const parts = [
    `${name}=${value}`,
    `Path=${overrides.path || "/"}`,
    "HttpOnly",
    `SameSite=${overrides.sameSite || "Lax"}`,
  ];

  if (overrides.maxAge !== undefined) {
    parts.push(`Max-Age=${overrides.maxAge}`);
  }

  if (shouldUseSecureCookies(request)) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function md5(value) {
  return crypto.createHash("md5").update(String(value)).digest("hex");
}

function isValidUsername(username) {
  return USERNAME_REGEX.test(String(username));
}

function getSafeImagiPath(username) {
  const candidatePath = path.resolve(IMAGI_ROOT, String(username));
  const rootPath = path.resolve(IMAGI_ROOT);
  if (candidatePath !== rootPath && !candidatePath.startsWith(`${rootPath}${path.sep}`)) {
    throw new Error("Unsafe imagi path");
  }
  return candidatePath;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scryptAsync(String(password), salt, 64);
  return `scrypt:${salt}:${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, storedHash) {
  if (!storedHash) {
    return { valid: false, needsUpgrade: false };
  }

  if (storedHash.startsWith("scrypt:")) {
    const [, salt, expectedHex] = storedHash.split(":");
    if (!salt || !expectedHex) {
      return { valid: false, needsUpgrade: false };
    }

    const expectedBuffer = Buffer.from(expectedHex, "hex");
    const derivedKey = await scryptAsync(String(password), salt, expectedBuffer.length);
    const valid = expectedBuffer.length === derivedKey.length
      && crypto.timingSafeEqual(expectedBuffer, derivedKey);
    return { valid, needsUpgrade: false };
  }

  const valid = md5(password) === storedHash;
  return { valid, needsUpgrade: valid };
}

function ensureAppState() {
  fs.mkdirSync(DATA_ROOT, { recursive: true });
  fs.mkdirSync(UIMG_ROOT, { recursive: true });
}

function initializeDatabase() {
  userDatabase = new DatabaseSync(USERS_DB_PATH);
  userDatabase.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password TEXT NOT NULL,
      email TEXT NOT NULL,
      create_datetime TEXT NOT NULL
    )
  `);

  chatDatabase = new DatabaseSync(CHAT_DB_PATH);
  chatDatabase.exec(`
    CREATE TABLE IF NOT EXISTS chat_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      display_name TEXT,
      username TEXT,
      is_registered INTEGER NOT NULL DEFAULT 0,
      avatar_name TEXT,
      message_text TEXT,
      image_name TEXT,
      raw_html TEXT,
      created_at TEXT NOT NULL
    )
  `);
  chatDatabase.exec(`
    CREATE TABLE IF NOT EXISTS chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      html TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  migrateLegacyLogIfNeeded();
}

function migrateLegacyLogIfNeeded() {
  const eventTotal = chatDatabase.prepare("SELECT COUNT(*) AS total FROM chat_events").get().total;
  if (eventTotal > 0) {
    return;
  }

  const hasLegacyTable = chatDatabase
    .prepare("SELECT COUNT(*) AS total FROM sqlite_master WHERE type = 'table' AND name = 'chat_messages'")
    .get().total > 0;

  if (hasLegacyTable) {
    const legacyRows = chatDatabase
      .prepare("SELECT html, created_at FROM chat_messages ORDER BY id ASC")
      .all();

    if (legacyRows.length > 0) {
      const insertLegacyEvent = chatDatabase.prepare(`
        INSERT INTO chat_events (event_type, raw_html, created_at)
        VALUES ('legacy_html', ?, ?)
      `);
      for (const row of legacyRows) {
        insertLegacyEvent.run(row.html, row.created_at);
      }
      return;
    }
  }

  if (!fs.existsSync(LOG_PATH)) {
    return;
  }

  const legacyHtml = fs.readFileSync(LOG_PATH, "utf8");
  if (!legacyHtml.trim()) {
    return;
  }

  chatDatabase
    .prepare("INSERT INTO chat_events (event_type, raw_html, created_at) VALUES ('legacy_html', ?, ?)")
    .run(legacyHtml, formatDateTime());
}

function parseCookies(header = "") {
  return header
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((cookies, part) => {
      const separatorIndex = part.indexOf("=");
      if (separatorIndex === -1) {
        return cookies;
      }

      const key = part.slice(0, separatorIndex);
      const rawValue = part.slice(separatorIndex + 1);
      cookies[key] = decodeURIComponent(rawValue);
      return cookies;
    }, {});
}

function createSession(request, response, payload) {
  const sid = crypto.randomBytes(24).toString("hex");
  sessions.set(sid, {
    ...payload,
    csrfToken: crypto.randomBytes(24).toString("hex"),
  });
  response.setHeader("Set-Cookie", buildCookie("sid", sid, request));
}

function clearSession(request, response, sid) {
  if (sid) {
    sessions.delete(sid);
  }
  response.setHeader("Set-Cookie", buildCookie("sid", "", request, { maxAge: 0 }));
}

function getSession(request) {
  const cookies = parseCookies(request.headers.cookie);
  return {
    sid: cookies.sid || "",
    session: cookies.sid ? sessions.get(cookies.sid) || null : null,
  };
}

function verifyCsrf(session, candidate) {
  return Boolean(session?.csrfToken) && typeof candidate === "string" && candidate === session.csrfToken;
}

function requireCsrf(request, response, session, candidate) {
  if (!verifyCsrf(session, candidate)) {
    writeText(response, 403, "Forbidden");
    return false;
  }
  return true;
}

function formatTime(date = new Date()) {
  return new Intl.DateTimeFormat("en-US", {
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  }).format(date);
}

function formatDateTime(date = new Date()) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function formatStoredDateTime(value) {
  if (!value) {
    return "";
  }

  const normalized = value.replace(" ", "T");
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) {
    return "";
  }

  return formatTime(parsed);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalSize = 0;

    request.on("data", (chunk) => {
      chunks.push(chunk);
      totalSize += chunk.length;
      if (totalSize > 10_000_000) {
        request.destroy();
        reject(new Error("Request body too large"));
      }
    });

    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function parseFormUrlEncoded(bodyBuffer) {
  return new URLSearchParams(bodyBuffer.toString("utf8"));
}

function parseMultipart(bodyBuffer, contentType = "") {
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  if (!match) {
    return [];
  }

  const boundary = Buffer.from(`--${match[1] || match[2]}`);
  const parts = [];
  let position = bodyBuffer.indexOf(boundary);

  while (position !== -1) {
    const nextBoundary = bodyBuffer.indexOf(boundary, position + boundary.length);
    if (nextBoundary === -1) {
      break;
    }

    let part = bodyBuffer.slice(position + boundary.length, nextBoundary);
    position = nextBoundary;

    if (part.length === 0) {
      continue;
    }

    if (part.slice(0, 2).equals(Buffer.from("\r\n"))) {
      part = part.slice(2);
    }

    if (part.length >= 2 && part.slice(part.length - 2).equals(Buffer.from("\r\n"))) {
      part = part.slice(0, -2);
    }

    if (part.equals(Buffer.from("--")) || part.length === 0) {
      continue;
    }

    const headerEnd = part.indexOf(Buffer.from("\r\n\r\n"));
    if (headerEnd === -1) {
      continue;
    }

    const rawHeaders = part.slice(0, headerEnd).toString("utf8");
    const content = part.slice(headerEnd + 4);
    const headers = {};

    for (const line of rawHeaders.split("\r\n")) {
      const separatorIndex = line.indexOf(":");
      if (separatorIndex === -1) {
        continue;
      }
      headers[line.slice(0, separatorIndex).trim().toLowerCase()] = line.slice(separatorIndex + 1).trim();
    }

    const disposition = headers["content-disposition"] || "";
    const nameMatch = disposition.match(/name="([^"]+)"/i);
    const fileNameMatch = disposition.match(/filename="([^"]*)"/i);

    parts.push({
      headers,
      name: nameMatch ? nameMatch[1] : "",
      filename: fileNameMatch ? path.basename(fileNameMatch[1]) : "",
      data: content,
    });
  }

  return parts;
}

function writeHtml(response, statusCode, html, headers = {}) {
  response.writeHead(statusCode, {
    "Content-Type": "text/html; charset=utf-8",
    ...headers,
  });
  response.end(html);
}

function writeText(response, statusCode, text, headers = {}) {
  response.writeHead(statusCode, {
    "Content-Type": "text/plain; charset=utf-8",
    ...headers,
  });
  response.end(text);
}

function redirect(response, location, headers = {}) {
  response.writeHead(302, {
    Location: location,
    ...headers,
  });
  response.end();
}

function insertChatEvent(event) {
  const result = chatDatabase.prepare(`
    INSERT INTO chat_events (
      event_type,
      display_name,
      username,
      is_registered,
      avatar_name,
      message_text,
      image_name,
      raw_html,
      created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    event.event_type,
    event.display_name || null,
    event.username || null,
    event.is_registered ? 1 : 0,
    event.avatar_name || null,
    event.message_text || null,
    event.image_name || null,
    event.raw_html || null,
    event.created_at || formatDateTime()
  );

  const row = chatDatabase.prepare(`
    SELECT
      id,
      event_type,
      display_name,
      username,
      is_registered,
      avatar_name,
      message_text,
      image_name,
      raw_html,
      created_at
    FROM chat_events
    WHERE id = ?
  `).get(Number(result.lastInsertRowid));

  broadcastChatEvent(row);
  return row;
}

function resolveAvatarSrc(isRegistered, avatarName) {
  const preferredName = avatarName || (isRegistered ? "default" : "rando");
  const preferredPath = path.join(IMAGI_ROOT, preferredName);
  if (fs.existsSync(preferredPath)) {
    return `/imagi/${encodeURIComponent(preferredName)}`;
  }

  const fallbackName = isRegistered ? "default" : "rando";
  const fallbackPath = path.join(IMAGI_ROOT, fallbackName);
  if (fs.existsSync(fallbackPath)) {
    return `/imagi/${encodeURIComponent(fallbackName)}`;
  }

  return "/imagi/default";
}

function resolveUploadedImageSrc(imageName) {
  if (!imageName) {
    return "";
  }

  const localPath = path.join(UIMG_ROOT, imageName);
  if (!fs.existsSync(localPath)) {
    return "";
  }

  return `/uimg/${encodeURIComponent(imageName)}`;
}

function resolveRareAwooSrc(imageName) {
  if (!imageName) {
    return "";
  }

  const localPath = path.join(APP_ROOT, "rare_awoos", imageName);
  if (!fs.existsSync(localPath)) {
    return "";
  }

  return `/rare_awoos/${encodeURIComponent(imageName)}`;
}

function renderChatEvent(row) {
  if (row.event_type === "legacy_html") {
    return `<div class='msgln'><span class='left-info'>${escapeHtml(LEGACY_HISTORY_NOTICE)}</span><br></div>`;
  }

  if (row.event_type === "leave") {
    return `<div class='msgln'><span class='left-info'>User <b class='user-name-left'>${escapeHtml(row.display_name || "")}</b> has left the chat session.</span><br></div>`;
  }

  const displayName = escapeHtml(row.display_name || "");
  const avatarSrc = resolveAvatarSrc(Boolean(row.is_registered), row.avatar_name || "");
  const avatarHtml = `<img class="chat-avatar" src="${avatarSrc}" alt="">`;
  const timeHtml = `<span class='chat-time'>${escapeHtml(formatStoredDateTime(row.created_at))}</span>`;

  if (row.event_type === "image") {
    const imageSrc = resolveUploadedImageSrc(row.image_name || "");
    const imageHtml = imageSrc
      ? `<img class="chat-upload" src="${imageSrc}" alt="">`
      : `<span class='left-info'>[missing image]</span>`;

    return `\n <div class='msgln'><p>REG-USR! <b class='user-name'>${displayName}</b>${avatarHtml} ${timeHtml} <br>&gt; ${imageHtml}</p><br></div>`;
  }

  if (row.event_type === "rare_awoo") {
    const imageSrc = resolveRareAwooSrc(row.image_name || "");
    const imageHtml = imageSrc
      ? `<img class="chat-upload chat-awoo" src="${imageSrc}" alt="">`
      : `<span class='left-info'>[missing rare awoo]</span>`;

    return `\n <div class='msgln'><p>REG-USR! <b class='user-name'>${displayName}</b>${avatarHtml}${timeHtml} <br>&gt; ${imageHtml}</p></div>`;
  }

  if (row.is_registered) {
    return `\n <div class='msgln'><p>REG-USR! <b class='user-name'>${displayName}</b>${avatarHtml} ${timeHtml} <br>&gt; ${escapeHtml(row.message_text || "")}</p></div>`;
  }

  return `\n <div class='msgln'><p>NOTUSR:( ${timeHtml} <b class='user-name'>${displayName}</b>${avatarHtml}<br>${escapeHtml(row.message_text || "")}</p></div>`;
}

async function loadChatState() {
  const rows = chatDatabase.prepare(`
    SELECT
      id,
      event_type,
      display_name,
      username,
      is_registered,
      avatar_name,
      message_text,
      image_name,
      raw_html,
      created_at
    FROM chat_events
    ORDER BY id ASC
  `).all();

  return {
    html: rows.map(renderChatEvent).join(""),
    lastEventId: rows.length > 0 ? rows[rows.length - 1].id : 0,
  };
}

async function loadLog() {
  const state = await loadChatState();
  return state.html;
}

function loadEventsAfterId(lastEventId) {
  return chatDatabase.prepare(`
    SELECT
      id,
      event_type,
      display_name,
      username,
      is_registered,
      avatar_name,
      message_text,
      image_name,
      raw_html,
      created_at
    FROM chat_events
    WHERE id > ?
    ORDER BY id ASC
  `).all(Number(lastEventId) || 0);
}

function writeStreamEvent(response, row) {
  response.write(`id: ${row.id}\n`);
  response.write(`event: chat\n`);
  response.write(`data: ${JSON.stringify({ id: row.id, html: renderChatEvent(row) })}\n\n`);
}

function broadcastChatEvent(row) {
  if (!row) {
    return;
  }

  for (const client of streamClients) {
    writeStreamEvent(client.response, row);
  }
}

function handleChatStream(request, response, url) {
  response.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-store",
    Connection: "keep-alive",
  });

  response.write(": connected\n\n");

  const lastEventId = request.headers["last-event-id"] || url.searchParams.get("since") || "0";
  const missedRows = loadEventsAfterId(lastEventId);
  for (const row of missedRows) {
    writeStreamEvent(response, row);
  }

  const client = { response };
  streamClients.add(client);

  const keepAlive = setInterval(() => {
    response.write(": keepalive\n\n");
  }, 20000);

  request.on("close", () => {
    clearInterval(keepAlive);
    streamClients.delete(client);
  });
}

function findUser(username) {
  return userDatabase
    .prepare("SELECT username, password, email, create_datetime FROM users WHERE username = ? COLLATE NOCASE")
    .get(String(username));
}

function createUser({ username, password, email, create_datetime }) {
  userDatabase
    .prepare("INSERT INTO users (username, password, email, create_datetime) VALUES (?, ?, ?, ?)")
    .run(username, password, email, create_datetime);
}

function updateUserPassword(username, passwordHash) {
  userDatabase
    .prepare("UPDATE users SET password = ? WHERE username = ? COLLATE NOCASE")
    .run(passwordHash, username);
}

async function copyDefaultImagi(username) {
  const source = path.join(IMAGI_ROOT, "default");
  const destination = getSafeImagiPath(username);
  await fs.promises.copyFile(source, destination);
}

function detectMimeFromBuffer(buffer) {
  if (buffer.length >= 8 && buffer.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return "image/png";
  }

  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return "image/jpeg";
  }

  if (buffer.length >= 6) {
    const signature = buffer.slice(0, 6).toString("ascii");
    if (signature === "GIF87a" || signature === "GIF89a") {
      return "image/gif";
    }
  }

  return "application/octet-stream";
}

function getImageDimensions(buffer) {
  if (buffer.length >= 24 && buffer.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return {
      width: buffer.readUInt32BE(16),
      height: buffer.readUInt32BE(20),
      mime: "image/png",
    };
  }

  if (buffer.length >= 10) {
    const signature = buffer.slice(0, 6).toString("ascii");
    if (signature === "GIF87a" || signature === "GIF89a") {
      return {
        width: buffer.readUInt16LE(6),
        height: buffer.readUInt16LE(8),
        mime: "image/gif",
      };
    }
  }

  if (buffer.length >= 4 && buffer[0] === 0xff && buffer[1] === 0xd8) {
    let offset = 2;
    while (offset < buffer.length) {
      if (buffer[offset] !== 0xff) {
        offset += 1;
        continue;
      }

      const marker = buffer[offset + 1];
      const blockLength = buffer.readUInt16BE(offset + 2);
      const isStartOfFrame = marker >= 0xc0 && marker <= 0xc3;
      if (isStartOfFrame && offset + 9 < buffer.length) {
        return {
          height: buffer.readUInt16BE(offset + 5),
          width: buffer.readUInt16BE(offset + 7),
          mime: "image/jpeg",
        };
      }
      offset += 2 + blockLength;
    }
  }

  return null;
}

function renderRegistrationPage(messageHtml = "") {
  return `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <title>Registration</title>
    <link rel="stylesheet" href="/style.css"/>
</head>
<body>
${messageHtml || `    <form class="form" action="/registration.php" method="post">
        <h1 class="login-title">Registration</h1>
        <input type="text" class="login-input" name="username" placeholder="Chat Name" required />
        <input type="text" class="login-input" name="email" placeholder="Auth Code (recovery)">
        <input type="password" class="login-input" name="password" placeholder="Password">
        <input type="submit" name="submit" value="Register" class="login-button">
        <p class="link"><a href="/login.php">Click to Login</a></p>
    </form>`}
</body>
</html>`;
}

function renderLoginPage(messageHtml = "") {
  return `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <title>Login</title>
    <link rel="stylesheet" href="/style.css"/>
</head>
<body>
${messageHtml || `    <form class="form" method="post" name="login" action="/login.php">
        <h1 class="login-title">Login</h1>
        <input type="text" class="login-input" name="username" placeholder="Username" autofocus="true"/>
        <input type="password" class="login-input" name="password" placeholder="Password"/>
        <input type="submit" value="Login" name="submit" class="login-button"/>
        <p><a href="/registration.php">New Registration</a></p>
        <p><a href="/chat.php">join as an unregistered user</a></p>
  </form>`}
</body>
</html>`;
}

function renderChatEntryPage(errorMessage = "") {
  const errorBlock = errorMessage ? `<span class="error">${escapeHtml(errorMessage)}</span>` : "";
  return `<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <title>Tuts+ Chat Application</title>
        <meta name="description" content="Tuts+ Chat Application" />
        <link rel="stylesheet" href="/chat-style.css" />
    </head>
    <body>
    ${errorBlock}
    <div id="loginform">
      <p>Please enter your chat handle</p>
      <form action="/chat.php" method="post">
        <input type="text" name="name" id="name" />
        <input type="submit" name="enter" id="enter" value="Enter" />
      </form>
    </div>
    </body>
</html>`;
}

function renderChatClient(postUrl, logoutUrl, csrfToken = "") {
  return `<script>
      const chatbox = document.getElementById("chatbox");
      const ding = new Audio("/ding.wav");
      ding.preload = "auto";
      const csrfToken = ${JSON.stringify(csrfToken)};
      if (chatbox) {
        chatbox.scrollTop = chatbox.scrollHeight;
      }

      function isNearBottom(element) {
        return element.scrollTop + element.clientHeight >= element.scrollHeight - 40;
      }

      function scrollToBottom(element) {
        element.scrollTo({ top: element.scrollHeight, behavior: "auto" });
      }

      function isAvatarImage(image) {
        const source = image.getAttribute("src") || "";
        return source.includes("/imagi/") || source.includes("engine/imagi/");
      }

      function stabilizeAvatarImage(image) {
        image.classList.add("chat-avatar");
        image.setAttribute("width", "48");
        image.setAttribute("height", "24");

        const source = image.getAttribute("src") || "";
        const fallbackSrc = source.includes("/imagi/rando") ? "/imagi/rando" : "/imagi/default";

        image.onerror = function () {
          if (image.dataset.fallbackApplied === "1") {
            image.style.visibility = "hidden";
            return;
          }

          image.dataset.fallbackApplied = "1";
          image.setAttribute("src", fallbackSrc);
        };
      }

      function normalizeChatMedia() {
        if (!chatbox) {
          return;
        }

        const images = chatbox.querySelectorAll("img");
        for (const image of images) {
          if (isAvatarImage(image)) {
            stabilizeAvatarImage(image);
          } else {
            image.classList.add("chat-upload");
          }
        }
      }

      function attachMediaStabilizers(shouldStickToBottom) {
        if (!chatbox || !shouldStickToBottom) {
          return;
        }

        const media = chatbox.querySelectorAll("img");
        for (const image of media) {
          if (image.complete) {
            continue;
          }

          const stabilize = () => scrollToBottom(chatbox);
          image.addEventListener("load", stabilize, { once: true });
          image.addEventListener("error", stabilize, { once: true });
        }
      }

      async function submitMessage(event) {
        event.preventDefault();
        const input = document.getElementById("usermsg");
        const clientmsg = input.value;
        if (!clientmsg.trim()) {
          input.value = "";
          return;
        }
        await fetch("${postUrl}", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-CSRF-Token": csrfToken
          },
          body: new URLSearchParams({ text: clientmsg, csrf_token: csrfToken })
        });
        input.value = "";
      }

      async function loadLog() {
        const shouldStickToBottom = isNearBottom(chatbox);
        const response = await fetch("/log.html", { cache: "no-store" });
        const html = await response.text();
        chatbox.innerHTML = html;
        normalizeChatMedia();
        attachMediaStabilizers(shouldStickToBottom);

        if (shouldStickToBottom) {
          scrollToBottom(chatbox);
        }
      }

      function appendChatHtml(payload, playSound) {
        if (!payload || typeof payload.html !== "string") {
          return;
        }

        const shouldStickToBottom = isNearBottom(chatbox);
        chatbox.insertAdjacentHTML("beforeend", payload.html);
        if (payload.id) {
          chatbox.dataset.lastEventId = String(payload.id);
        }
        normalizeChatMedia();
        attachMediaStabilizers(shouldStickToBottom);

        if (shouldStickToBottom) {
          scrollToBottom(chatbox);
        }

        if (playSound) {
          ding.currentTime = 0;
          ding.play().catch(() => {});
        }
      }

      function connectChatStream() {
        const since = encodeURIComponent(chatbox.dataset.lastEventId || "0");
        const stream = new EventSource("/events?since=" + since);
        stream.addEventListener("chat", function (event) {
          try {
            const payload = JSON.parse(event.data);
            appendChatHtml(payload, true);
          } catch (error) {
            console.error(error);
          }
        });

        stream.onerror = function () {
          // EventSource reconnects automatically.
        };
      }

      function initializePopoutPanels() {
        const panels = Array.from(document.querySelectorAll(".popout-panel"));

        function closePanel(panel) {
          panel.classList.remove("is-open");
          const toggle = panel.querySelector("[data-panel-toggle]");
          if (toggle) {
            toggle.setAttribute("aria-expanded", "false");
          }
        }

        function openPanel(panel) {
          for (const otherPanel of panels) {
            if (otherPanel !== panel) {
              closePanel(otherPanel);
            }
          }

          panel.classList.add("is-open");
          const toggle = panel.querySelector("[data-panel-toggle]");
          if (toggle) {
            toggle.setAttribute("aria-expanded", "true");
          }
        }

        for (const panel of panels) {
          const toggle = panel.querySelector("[data-panel-toggle]");
          if (!toggle) {
            continue;
          }

          toggle.addEventListener("click", function (event) {
            event.preventDefault();
            event.stopPropagation();

            if (panel.classList.contains("is-open")) {
              closePanel(panel);
            } else {
              openPanel(panel);
            }
          });

          const inner = panel.querySelector("#slideout_inner, #awoopanel_inner");
          if (inner) {
            inner.addEventListener("click", function (event) {
              event.stopPropagation();
            });
          }
        }

        document.addEventListener("click", function () {
          for (const panel of panels) {
            closePanel(panel);
          }
        });
      }

      const submitButton = document.getElementById("submitmsg");
      if (submitButton) {
        submitButton.addEventListener("click", submitMessage);
      }

      normalizeChatMedia();
      attachMediaStabilizers(true);
      connectChatStream();
      initializePopoutPanels();

      const exitButton = document.getElementById("exit");
      if (exitButton) {
        exitButton.addEventListener("submit", function (event) {
          event.preventDefault();
          const exit = window.confirm("Are you sure you want to end the session?");
          if (exit) {
            event.target.submit();
          }
        });
      }
    </script>`;
}

async function renderGuestChatPage(session) {
  const chatState = await loadChatState();
  return `<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <title>Tuts+ Chat Application</title>
        <meta name="description" content="Tuts+ Chat Application" />
        <link rel="stylesheet" href="/chat-style.css" />
    </head>
    <body>
      <div id="online">
        <p> testing</p>
        <p> testing</p>
        <p> testing</p>
        <p> testing</p>
        <p> testing</p>
        <p> testing</p>
      </div>
      <div id="wrapper">
        <div id="inner">
          <div id="menu">
            <p>/$&emsp;USERNAME:&emsp;${escapeHtml(session.name)}&emsp;
              <form id="exit" method="post" action="${"/logout.php"}" style="display:inline;">
                <input type="hidden" name="csrf_token" value="${escapeHtml(session.csrfToken || "")}">
                <button type="submit" style="background:none;border:0;color:red;font:inherit;cursor:pointer;">Exit Chat</button>
              </form>
            </p>
          </div>
          <div id="chatbox" data-last-event-id="${chatState.lastEventId}">${chatState.html}</div>
          <form name="message" action="">
            <input name="usermsg" type="text" id="usermsg" />
            <input name="submitmsg" type="submit" id="submitmsg" value="Send" />
          </form>
        </div>
      </div>
      ${renderChatClient("/post.php", "/logout.php", session.csrfToken || "")}
    </body>
</html>`;
}

async function renderDashboardPage(session, responseHtml = "") {
  const chatState = await loadChatState();
  const rareAwoos = Array.from({ length: 14 }, (_, index) => index + 1)
    .map((id) => `<form class="awoo-link" method="post" action="/rare_awoos/${id}.php">
        <input type="hidden" name="csrf_token" value="${escapeHtml(session.csrfToken)}">
        <button type="submit" style="background:none;border:0;padding:0;cursor:pointer;">
          <img src="/rare_awoos/${id}.png" width="64" height="64" alt="Rare awoo ${id}">
        </button>
      </form>`)
    .join("");
  return `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Dashboard - Client area</title>
    <link rel="stylesheet" href="/chat-style.css" />
    <link rel="stylesheet" href="/img-upload.css" />
    <link rel="stylesheet" href="/bitpanel.css" />
</head>
<body>
  <div class="online">
    <p>:3</p>
    <div id="slideout" class="popout-panel">
      <button type="button" class="panel-toggle" data-panel-toggle="slideout" aria-expanded="false" aria-controls="slideout_inner">
        <img src="/cpanel.png" alt="BitPanel" />
      </button>
      <div id="slideout_inner">
        <p>logged in as:</p>
        <p>${escapeHtml(session.username)}!</p>
        <div class="imagi"><p>IMAGI Control Panel</p>
          <form id="frm-image-upload" action="/dashboard.php" name="img" method="post" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="${escapeHtml(session.csrfToken)}">
            <div class="form-row">
              <p>Upload New Imagi</p>
              <div>
                <input type="file" class="file-input" name="file-input" style="border:2px solid #F1CBF2; color: #F1CBF2; background-color: black;">
              </div>
            </div>
            <div class="button-row">
              <input type="submit" id="btn-submit" name="upload" value="Upload" style="border:2px solid #F1CBF2; color: #F1CBF2; background-color: black;">
            </div>
          </form>
        </div>
        <p><br>
          <form id="logout-form" method="post" action="/logout.php" style="display:inline;">
            <input type="hidden" name="csrf_token" value="${escapeHtml(session.csrfToken)}">
            <button type="submit" style="background:none;border:0;color:red;font:inherit;cursor:pointer;">Logout</button>
          </form>
        </p>
      </div>
    </div>
  </div>
  <div id="wrapper">
    <div id="menu">
      <p>/$&emsp;USERNAME:&emsp;${escapeHtml(session.name)}</p>
    </div>
    <div id="chatbox" data-last-event-id="${chatState.lastEventId}">${chatState.html}</div>
    <form name="message" action="">
      <input name="usermsg" type="text" id="usermsg" />
      <input name="submitmsg" type="submit" id="submitmsg" value="Send" />
    </form>
    <div id="awoopanel" class="popout-panel">
      <button type="button" class="panel-toggle" data-panel-toggle="awoopanel" aria-expanded="false" aria-controls="awoopanel_inner">
        <img src="/media/chat/awoos.png" alt="Rare Awoos">
      </button>
      <div id="awoopanel_inner">
        <div class="awoo-grid">${rareAwoos}</div>
      </div>
    </div>
  </div>
  ${responseHtml}
  ${renderChatClient("/post-reg.php", "/logout.php", session.csrfToken)}
</body>
</html>`;
}

function renderResponseMessage(type, message) {
  return `<div class="response ${escapeHtml(type)}">${message}</div>`;
}

function requireAuth(request, response) {
  const { sid, session } = getSession(request);
  if (!session || !session.username) {
    clearSession(request, response, sid);
    redirect(response, "/login.php");
    return null;
  }
  return { sid, session };
}

async function handleRegistrationGet(response) {
  writeHtml(response, 200, renderRegistrationPage());
}

async function handleRegistrationPost(request, response) {
  const params = parseFormUrlEncoded(await readBody(request));
  const username = (params.get("username") || "").trim();
  const email = (params.get("email") || "").trim();
  const password = (params.get("password") || "").trim();

  if (!username || !email || !password) {
    writeHtml(response, 400, renderRegistrationPage(`<div class='form'>
                  <p>Required fields are missing.</p>
                  <p class='link'>Click here to <a href='/registration.php'>registration</a> again.</p>
                  </div>`));
    return;
  }

  if (!isValidUsername(username)) {
    writeHtml(response, 400, renderRegistrationPage(`<div class='form'>
                  <p>Usernames must be 1-32 characters and use only letters, numbers, underscores, or hyphens.</p>
                  <p class='link'>Click here to <a href='/registration.php'>registration</a> again.</p>
                  </div>`));
    return;
  }

  if (findUser(username)) {
    writeHtml(response, 409, renderRegistrationPage(`<div class='form'>
                  <p>Required fields are missing.</p>
                  <p class='link'>Click here to <a href='/registration.php'>registration</a> again.</p>
                  </div>`));
    return;
  }

  createUser({
    username,
    password: await hashPassword(password),
    email,
    create_datetime: formatDateTime(),
  });
  await copyDefaultImagi(username);

  writeHtml(response, 200, renderRegistrationPage(`<div class='form'>
                  <p>Successfully registered. Fun features to come :3</p><br/>
                  <p class='link'>Click here to <a href='/login.php'>Login</a></p>
                  </div>`));
}

async function handleLoginGet(response) {
  writeHtml(response, 200, renderLoginPage());
}

async function handleLoginPost(request, response) {
  const params = parseFormUrlEncoded(await readBody(request));
  const username = (params.get("username") || "").trim();
  const password = (params.get("password") || "").trim();
  const user = findUser(username);

  const verification = user ? await verifyPassword(password, user.password) : { valid: false, needsUpgrade: false };
  if (!user || !verification.valid) {
    writeHtml(response, 200, renderLoginPage(`<div class='form'>
                  <h3>Incorrect Username/password.</h3><br/>
                  <p class='link'>Click here to <a href='/login.php'>Login</a> again.</p>
                  </div>`));
    return;
  }

  if (verification.needsUpgrade) {
    updateUserPassword(user.username, await hashPassword(password));
  }

  createSession(request, response, {
    username: user.username,
    name: user.username,
  });
  redirect(response, "/dashboard.php");
}

async function handleLogout(request, response) {
  const { sid, session } = getSession(request);
  const params = parseFormUrlEncoded(await readBody(request));
  if (session && !requireCsrf(request, response, session, params.get("csrf_token") || request.headers["x-csrf-token"])) {
    return;
  }
  clearSession(request, response, sid);
  redirect(response, "/login.php");
}

async function handleGuestChatGet(request, response, url) {
  const { sid, session } = getSession(request);

  if (url.searchParams.get("logout") === "true") {
    if (session?.name) {
      insertChatEvent({
        event_type: "leave",
        display_name: session.name,
      });
    }
    clearSession(request, response, sid);
    redirect(response, "/login.php");
    return;
  }

  if (!session?.name) {
    writeHtml(response, 200, renderChatEntryPage());
    return;
  }

  writeHtml(response, 200, await renderGuestChatPage(session));
}

async function handleGuestChatPost(request, response) {
  const params = parseFormUrlEncoded(await readBody(request));
  const name = (params.get("name") || "").trim();

  if (!name) {
    writeHtml(response, 400, renderChatEntryPage("Please type in a name"));
    return;
  }

  createSession(request, response, { name });
  redirect(response, "/chat.php");
}

async function handleDashboardGet(request, response, url) {
  if (url.searchParams.get("logout") === "true") {
    await handleLogout(request, response);
    return;
  }

  const auth = requireAuth(request, response);
  if (!auth) {
    return;
  }

  writeHtml(response, 200, await renderDashboardPage(auth.session));
}

async function handleDashboardPost(request, response) {
  const auth = requireAuth(request, response);
  if (!auth) {
    return;
  }

  const body = await readBody(request);
  const parts = parseMultipart(body, request.headers["content-type"]);
  const csrfPart = parts.find((part) => part.name === "csrf_token");
  const csrfToken = csrfPart ? csrfPart.data.toString("utf8") : request.headers["x-csrf-token"];
  if (!requireCsrf(request, response, auth.session, csrfToken)) {
    return;
  }
  const filePart = parts.find((part) => part.name === "file-input");

  let responseMessage = "";
  if (!filePart || !filePart.data.length) {
    responseMessage = renderResponseMessage("error", "<p>Choose image file to upload.</p>");
  } else {
    const extension = path.extname(filePart.filename).slice(1).toLowerCase();
    const allowedExtensions = ["png", "jpg", "jpeg"];
    const dimensions = getImageDimensions(filePart.data);

    if (!allowedExtensions.includes(extension)) {
      responseMessage = renderResponseMessage("error", "<p>valiid images only. Only 48x24px PNG/JPEG allowed.</p>");
    } else if (filePart.data.length > 10000) {
      responseMessage = renderResponseMessage("error", "<p>Image size exceeds 2kb</p>");
    } else if (!dimensions || dimensions.width > 48 || dimensions.height > 24) {
      responseMessage = renderResponseMessage("error", "<p>valiid images only. Only 48x24px PNG/JPEG allowed.</p>");
    } else {
      await fs.promises.writeFile(getSafeImagiPath(auth.session.username), filePart.data);
      responseMessage = renderResponseMessage("success", "<p>IMAGI uploaded successfully.</p>");
    }
  }

  writeHtml(response, 200, await renderDashboardPage(auth.session, responseMessage));
}

async function handleGuestPost(request, response) {
  const { session } = getSession(request);
  if (!session?.name) {
    writeText(response, 401, "Not logged in");
    return;
  }

  const params = parseFormUrlEncoded(await readBody(request));
  if (!requireCsrf(request, response, session, params.get("csrf_token") || request.headers["x-csrf-token"])) {
    return;
  }
  const text = (params.get("text") || "").trim();
  if (!text) {
    response.writeHead(204);
    response.end();
    return;
  }
  insertChatEvent({
    event_type: "message",
    display_name: session.name,
    is_registered: false,
    avatar_name: "rando",
    message_text: text,
  });
  response.writeHead(204);
  response.end();
}

async function handleRegisteredPost(request, response) {
  const auth = requireAuth(request, response);
  if (!auth) {
    return;
  }

  const params = parseFormUrlEncoded(await readBody(request));
  if (!requireCsrf(request, response, auth.session, params.get("csrf_token") || request.headers["x-csrf-token"])) {
    return;
  }
  const text = (params.get("text") || "").trim();
  if (!text) {
    response.writeHead(204);
    response.end();
    return;
  }
  insertChatEvent({
    event_type: "message",
    display_name: auth.session.name,
    username: auth.session.username,
    is_registered: true,
    avatar_name: auth.session.username,
    message_text: text,
  });
  response.writeHead(204);
  response.end();
}

async function handleRareAwoo(request, response, rareAwooName) {
  const auth = requireAuth(request, response);
  if (!auth) {
    return;
  }

  const params = parseFormUrlEncoded(await readBody(request));
  if (!requireCsrf(request, response, auth.session, params.get("csrf_token") || request.headers["x-csrf-token"])) {
    return;
  }

  const fileName = `${rareAwooName}.png`;
  const localPath = path.join(APP_ROOT, "rare_awoos", fileName);
  if (!fs.existsSync(localPath)) {
    writeText(response, 404, "Not found");
    return;
  }

  insertChatEvent({
    event_type: "rare_awoo",
    display_name: auth.session.name,
    username: auth.session.username,
    is_registered: true,
    avatar_name: auth.session.username,
    image_name: fileName,
  });
  redirect(response, "/dashboard.php");
}

async function serveStaticFile(response, filePath) {
  const data = await fs.promises.readFile(filePath);
  const extension = path.extname(filePath).toLowerCase();
  const contentType = extension ? MIME_TYPES[extension] || "application/octet-stream" : detectMimeFromBuffer(data);
  response.writeHead(200, { "Content-Type": contentType });
  response.end(data);
}

function resolvePath(root, requestPath) {
  const safePath = path.normalize(requestPath).replace(/^(\.\.[\\/])+/, "");
  const filePath = path.join(root, safePath);
  if (!filePath.startsWith(root)) {
    return null;
  }
  return filePath;
}

async function handleStatic(response, pathname) {
  if (pathname.toLowerCase().endsWith(".php")) {
    writeText(response, 404, "Not found");
    return;
  }

  const filePath = resolvePath(APP_ROOT, pathname.slice(1));
  if (!filePath) {
    writeText(response, 403, "Forbidden");
    return;
  }

  try {
    const stats = await fs.promises.stat(filePath);
    if (!stats.isFile()) {
      writeText(response, 404, "Not found");
      return;
    }
    await serveStaticFile(response, filePath);
  } catch (error) {
    if (error.code === "ENOENT") {
      writeText(response, 404, "Not found");
      return;
    }
    throw error;
  }
}

ensureAppState();
initializeDatabase();

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);

    if (request.method === "GET" && url.pathname === "/") {
      redirect(response, "/login.php");
      return;
    }

    if (url.pathname === "/registration.php") {
      if (request.method === "GET") {
        await handleRegistrationGet(response);
        return;
      }
      if (request.method === "POST") {
        await handleRegistrationPost(request, response);
        return;
      }
    }

    if (url.pathname === "/login.php") {
      if (request.method === "GET") {
        await handleLoginGet(response);
        return;
      }
      if (request.method === "POST") {
        await handleLoginPost(request, response);
        return;
      }
    }

    if (request.method === "POST" && url.pathname === "/logout.php") {
      await handleLogout(request, response);
      return;
    }

    if (url.pathname === "/chat.php") {
      if (request.method === "GET") {
        await handleGuestChatGet(request, response, url);
        return;
      }
      if (request.method === "POST") {
        await handleGuestChatPost(request, response);
        return;
      }
    }

    if (url.pathname === "/dashboard.php") {
      if (request.method === "GET") {
        await handleDashboardGet(request, response, url);
        return;
      }
      if (request.method === "POST") {
        await handleDashboardPost(request, response);
        return;
      }
    }

    if (request.method === "POST" && url.pathname === "/post.php") {
      await handleGuestPost(request, response);
      return;
    }

    if (request.method === "POST" && url.pathname === "/post-reg.php") {
      await handleRegisteredPost(request, response);
      return;
    }

    const rareAwooMatch = url.pathname.match(/^\/rare_awoos\/(\d+)\.php$/);
    if (request.method === "POST" && rareAwooMatch) {
      await handleRareAwoo(request, response, rareAwooMatch[1]);
      return;
    }

    if (request.method === "GET" && url.pathname === "/log.html") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      });
      response.end(await loadLog());
      return;
    }

    if (request.method === "GET" && url.pathname === "/events") {
      handleChatStream(request, response, url);
      return;
    }

    if (request.method === "GET") {
      await handleStatic(response, url.pathname);
      return;
    }

    writeText(response, 405, "Method not allowed");
  } catch (error) {
    console.error(error);
    writeText(response, 500, "Internal server error");
  }
});

server.listen(PORT, () => {
  console.log(`Engine clone server running at http://localhost:${PORT}/login.php`);
});
