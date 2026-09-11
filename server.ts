import express from "express";
import { createProxyMiddleware } from "http-proxy-middleware";
import { spawn, execSync, ChildProcess } from "child_process";
import http from "http";

const PORT = 3000;
const FLASK_PORT = 5000;
const FLASK_TARGET = `http://127.0.0.1:${FLASK_PORT}`;

let flaskProcess: ChildProcess | null = null;
let isShuttingDown = false;

function checkFlaskHealth(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get(`${FLASK_TARGET}/health`, (res) => {
      resolve(res.statusCode === 200);
    });
    req.on("error", () => resolve(false));
    req.setTimeout(1000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

function verifyPythonEnvironment() {
  try {
    execSync("python3 -c 'import flask'", { stdio: "ignore" });
    console.log("[StorageOS] Python Flask environment is available.");
  } catch {
    console.log("[StorageOS] Installing Python dependencies (Flask, Gunicorn)...");
    try {
      execSync(
        'DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" --no-install-recommends python3-pip python3-flask gunicorn',
        {
          stdio: "inherit",
          env: { ...process.env, DEBIAN_FRONTEND: "noninteractive" },
        }
      );
      console.log("[StorageOS] Python dependencies installed successfully.");
    } catch (e) {
      console.error("[StorageOS] Failed to install via apt-get, trying pip:", e);
      try {
        execSync("python3 -m pip install -r requirements.txt --break-system-packages", { stdio: "inherit" });
      } catch (err) {
        console.error("[StorageOS] pip install also failed:", err);
      }
    }
  }
}

function spawnFlaskBackend() {
  if (isShuttingDown) return;

  let hasGunicorn = false;
  try {
    execSync("python3 -m gunicorn --version", { stdio: "ignore" });
    hasGunicorn = true;
  } catch {
    hasGunicorn = false;
  }

  const cmd = "python3";
  const args = hasGunicorn
    ? ["-m", "gunicorn", "-w", "2", "-b", `127.0.0.1:${FLASK_PORT}`, "--access-logfile", "-", "app.app:create_app()"]
    : ["-m", "flask", "--app", "app.app", "run", "--host=127.0.0.1", `--port=${FLASK_PORT}`];

  console.log(`[StorageOS] Launching Flask backend with ${hasGunicorn ? "Gunicorn" : "Flask Dev Server"}...`);

  flaskProcess = spawn(cmd, args, {
    stdio: "inherit",
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
  });

  flaskProcess.on("exit", (code, signal) => {
    console.log(`[StorageOS] Flask backend exited (code=${code}, signal=${signal})`);
    flaskProcess = null;
    if (!isShuttingDown) {
      console.log("[StorageOS] Restarting Flask backend in 2 seconds...");
      setTimeout(spawnFlaskBackend, 2000);
    }
  });
}

async function ensureFlaskRunning() {
  const healthy = await checkFlaskHealth();
  if (healthy) {
    console.log(`[StorageOS] Flask backend is already healthy on port ${FLASK_PORT}`);
    return;
  }

  verifyPythonEnvironment();
  spawnFlaskBackend();

  // Wait for Flask to become ready (up to 30 seconds)
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 500));
    const isReady = await checkFlaskHealth();
    if (isReady) {
      console.log(`[StorageOS] Flask backend is ready on port ${FLASK_PORT}`);
      return;
    }
  }
  console.warn("[StorageOS] Warning: Flask backend did not respond to /health in time, continuing...");
}

async function startServer() {
  await ensureFlaskRunning();

  const app = express();
  app.set("trust proxy", true);

  // Proxy all requests directly to the StorageOS Python Flask backend
  app.use(
    "/",
    createProxyMiddleware({
      target: FLASK_TARGET,
      changeOrigin: false,
      ws: true,
      xfwd: false,
      proxyTimeout: 60000,
      timeout: 60000,
      on: {
        proxyReq: (proxyReq, req) => {
          // Accurately forward original protocol from Cloud Run / Nginx
          const expressReq = req as any;
          const proto = (expressReq.headers["x-forwarded-proto"] as string) || (expressReq.secure ? "https" : "http");
          proxyReq.setHeader("x-forwarded-proto", proto);
          const host = (expressReq.headers["x-forwarded-host"] as string) || expressReq.headers.host || "localhost";
          proxyReq.setHeader("x-forwarded-host", host);
          if (expressReq.headers["x-forwarded-for"]) {
            proxyReq.setHeader("x-forwarded-for", expressReq.headers["x-forwarded-for"]);
          }
        },
        error: (err, req, res) => {
          console.error("[StorageOS Proxy Error]", err.message);
          if (res && "writeHead" in res && !res.headersSent) {
            res.writeHead(503, { "Content-Type": "text/html", "Retry-After": "3" });
            res.end(`
            <!DOCTYPE html>
            <html>
              <head>
                <meta charset="utf-8">
                <meta http-equiv="refresh" content="2">
                <title>StorageOS Starting...</title>
                <style>
                  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #09090b; color: #fafafa; }
                  .card { text-align: center; padding: 40px; background: #18181b; border: 1px solid #27272a; border-radius: 12px; max-width: 400px; }
                  .spinner { width: 32px; height: 32px; border: 3px solid #3f3f46; border-top-color: #ef4444; border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 20px; }
                  @keyframes spin { to { transform: rotate(360deg); } }
                </style>
              </head>
              <body>
                <div class="card">
                  <div class="spinner"></div>
                  <h2 style="margin:0 0 10px;">StorageOS Starting...</h2>
                  <p style="color:#a1a1aa;margin:0;font-size:14px;">The storage engine is initializing. Refreshing automatically...</p>
                </div>
              </body>
            </html>
          `);
          }
        },
      },
    })
  );

  const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`[StorageOS] Gateway proxy listening on http://0.0.0.0:${PORT}`);
  });

  const cleanup = () => {
    isShuttingDown = true;
    if (flaskProcess) {
      console.log("[StorageOS] Terminating Flask process...");
      flaskProcess.kill("SIGTERM");
    }
    server.close(() => {
      process.exit(0);
    });
  };

  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);
}

startServer().catch((err) => {
  console.error("[StorageOS] Critical startup error:", err);
});
