const { app, BrowserWindow, shell } = require("electron");
const path = require("path");

// Set environment for Electron mode
process.env.EASYCLAW_ELECTRON = "1";
process.env.EASYCLAW_HOST = "127.0.0.1";
process.env.EASYCLAW_DB_PATH = path.join(app.getPath("userData"), "users.db");

let mainWindow = null;
let serverReady = false;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: "EasyClaw",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  // Wait for server to be ready, then load
  const loadApp = () => {
    if (serverReady) {
      mainWindow.loadURL("http://127.0.0.1:3000/lp.html");
    } else {
      setTimeout(loadApp, 200);
    }
  };
  loadApp();

  // Open external links in default browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http") && !url.includes("127.0.0.1:3000") && !url.includes("localhost:3000")) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "allow" };
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  // Start Express server
  try {
    const server = require("../server.js");
    serverReady = true;
    console.log("[Electron] Express server started");
  } catch (e) {
    console.error("[Electron] Failed to start server:", e.message);
    // Try again after a short delay
    setTimeout(() => {
      try {
        require("../server.js");
        serverReady = true;
      } catch (e2) {
        console.error("[Electron] Server failed permanently:", e2.message);
      }
    }, 1000);
  }

  createWindow();
});

app.on("window-all-closed", () => {
  app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// Cleanup on quit
app.on("before-quit", () => {
  // Server cleanup happens automatically when process exits
  console.log("[Electron] Shutting down...");
});
