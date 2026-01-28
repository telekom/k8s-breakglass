import express from "express";
import cors from "cors";
import {
  breakglassEscalations,
  createSessionFromRequest,
  identityProviderConfig,
  listSessions,
  multiIDPConfig,
  runtimeConfig,
  findSession,
  updateSessionState,
  CURRENT_USER_EMAIL,
  // Debug session exports
  listDebugSessions,
  findDebugSession,
  createDebugSession,
  updateDebugSessionState,
  joinDebugSession,
  leaveDebugSession,
  renewDebugSession,
  listDebugSessionTemplates,
  findDebugSessionTemplate,
  listDebugPodTemplates,
  findDebugPodTemplate,
  getTemplateClusters,
} from "./data.mjs";

const app = express();
const port = Number(process.env.MOCK_API_PORT || 8080);

app.use(cors());
app.use(express.json());

app.get("/healthz", (_req, res) => {
  res.json({ ok: true, user: CURRENT_USER_EMAIL });
});

app.get("/api/config", (_req, res) => {
  res.json(runtimeConfig);
});

app.get("/api/identity-provider", (_req, res) => {
  res.json(identityProviderConfig);
});

app.get("/api/config/idps", (_req, res) => {
  res.json(multiIDPConfig);
});

app.get("/api/breakglassEscalations", (_req, res) => {
  res.json(breakglassEscalations);
});

app.get("/api/breakglassSessions", (req, res) => {
  const sessions = listSessions(req.query || {});
  res.json(sessions);
});

app.post("/api/breakglassSessions", (req, res) => {
  const body = req.body || {};
  const session = createSessionFromRequest(body);
  res.status(201).json({ message: "mock session created", session });
});

app.post("/api/breakglassSessions/:name/approve", (req, res) => {
  const name = req.params.name;
  const updated = updateSessionState(name, "Approved", { reason: req.body?.reason });
  if (!updated) {
    return res.status(404).json({ message: `session ${name} not found` });
  }
  res.json({ message: "session approved", session: updated });
});

app.post("/api/breakglassSessions/:name/reject", (req, res) => {
  const name = req.params.name;
  const updated = updateSessionState(name, "Rejected", { reason: req.body?.reason });
  if (!updated) {
    return res.status(404).json({ message: `session ${name} not found` });
  }
  res.json({ message: "session rejected", session: updated });
});

app.post("/api/breakglassSessions/:name/drop", (req, res) => {
  const name = req.params.name;
  const updated = updateSessionState(name, "Dropped", { reason: req.body?.reason });
  if (!updated) {
    return res.status(404).json({ message: `session ${name} not found` });
  }
  res.json({ message: "session dropped", session: updated });
});

app.post("/api/breakglassSessions/:name/withdraw", (req, res) => {
  const name = req.params.name;
  const updated = updateSessionState(name, "Withdrawn", { reason: req.body?.reason });
  if (!updated) {
    return res.status(404).json({ message: `session ${name} not found` });
  }
  res.json({ message: "session withdrawn", session: updated });
});

app.post("/api/breakglassSessions/:name/test", (_req, res) => {
  res.json({ message: "mock test endpoint" });
});

app.post("/api/breakglassSessions/:name/refresh", (_req, res) => {
  res.json({ message: "mock refresh" });
});

app.get("/api/breakglassSessions/:name", (req, res) => {
  const session = findSession(req.params.name);
  if (!session) {
    return res.status(404).json({ message: "session not found" });
  }
  res.json(session);
});

// ============================================================================
// DEBUG SESSION API ROUTES
// ============================================================================

// List debug sessions
app.get("/api/debugSessions", (req, res) => {
  const result = listDebugSessions(req.query || {});
  res.json(result);
});

// List debug session templates
app.get("/api/debugSessions/templates", (req, res) => {
  const result = listDebugSessionTemplates();
  res.json(result);
});

// Get debug session template
app.get("/api/debugSessions/templates/:name", (req, res) => {
  const template = findDebugSessionTemplate(req.params.name);
  if (!template) {
    return res.status(404).json({ message: "template not found" });
  }
  res.json(template);
});

// Get available clusters for a template with resolved constraints
app.get("/api/debugSessions/templates/:name/clusters", (req, res) => {
  const result = getTemplateClusters(req.params.name);
  if (!result) {
    return res.status(404).json({ message: "template not found" });
  }
  res.json(result);
});

// List debug pod templates
app.get("/api/debugSessions/podTemplates", (req, res) => {
  const result = listDebugPodTemplates();
  res.json(result);
});

// Get debug pod template
app.get("/api/debugSessions/podTemplates/:name", (req, res) => {
  const template = findDebugPodTemplate(req.params.name);
  if (!template) {
    return res.status(404).json({ message: "pod template not found" });
  }
  res.json(template);
});

// Get debug session
app.get("/api/debugSessions/:name", (req, res) => {
  const session = findDebugSession(req.params.name);
  if (!session) {
    return res.status(404).json({ message: "debug session not found" });
  }
  res.json(session);
});

// Create debug session
app.post("/api/debugSessions", (req, res) => {
  const session = createDebugSession(req.body || {});
  res.status(201).json(session);
});

// Join debug session
app.post("/api/debugSessions/:name/join", (req, res) => {
  const role = req.body?.role || "viewer";
  const session = joinDebugSession(req.params.name, role);
  if (!session) {
    return res.status(404).json({ message: "debug session not found" });
  }
  res.json(session);
});

// Leave debug session
app.post("/api/debugSessions/:name/leave", (req, res) => {
  const session = leaveDebugSession(req.params.name);
  if (!session) {
    return res.status(404).json({ message: "debug session not found" });
  }
  res.json(session);
});

// Renew debug session
app.post("/api/debugSessions/:name/renew", (req, res) => {
  const extendBy = req.body?.extendBy || "1h";
  const session = renewDebugSession(req.params.name, extendBy);
  if (!session) {
    return res.status(404).json({ message: "debug session not found" });
  }
  res.json(session);
});

// Terminate debug session
app.post("/api/debugSessions/:name/terminate", (req, res) => {
  const session = updateDebugSessionState(req.params.name, "Terminated", { reason: req.body?.reason });
  if (!session) {
    return res.status(404).json({ message: "debug session not found" });
  }
  res.json(session);
});

// Approve debug session
app.post("/api/debugSessions/:name/approve", (req, res) => {
  const session = updateDebugSessionState(req.params.name, "Active", { approvedBy: CURRENT_USER_EMAIL });
  if (!session) {
    return res.status(404).json({ message: "debug session not found" });
  }
  res.json(session);
});

// Reject debug session
app.post("/api/debugSessions/:name/reject", (req, res) => {
  const session = updateDebugSessionState(req.params.name, "Failed", {
    rejectedBy: CURRENT_USER_EMAIL,
    reason: req.body?.reason || "Rejected",
  });
  if (!session) {
    return res.status(404).json({ message: "debug session not found" });
  }
  res.json(session);
});

app.use((req, res, next) => {
  if (req.path.startsWith("/api")) {
    console.warn("[mock-api] Unhandled API route", req.method, req.path);
    return res.status(404).json({ message: "mock route not implemented" });
  }
  return next();
});

app.use((err, _req, res, _next) => {
  console.error("[mock-api] Unhandled error:", err);
  if (res.headersSent && typeof _next === "function") {
    return _next(err);
  }
  return res.status(err?.status || 500).json({ message: "Internal server error", error: err?.message || String(err) });
});

app.listen(port, () => {
  console.log(`[mock-api] listening on http://localhost:${port}`);
});
