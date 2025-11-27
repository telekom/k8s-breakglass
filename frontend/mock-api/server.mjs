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

app.use((req, res, next) => {
  if (req.path.startsWith("/api")) {
    console.warn("[mock-api] Unhandled API route", req.method, req.path);
    return res.status(404).json({ message: "mock route not implemented" });
  }
  return next();
});

app.listen(port, () => {
  console.log(`[mock-api] listening on http://localhost:${port}`);
});
