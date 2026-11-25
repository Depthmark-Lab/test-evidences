// Hello World web service: GET /hello?name=... and GET /health.
import express from "express";

export function greeting(name) {
  const trimmed = typeof name === "string" ? name.trim() : "";
  return `Hello, ${trimmed || "world"}!`;
}

export function createApp() {
  const app = express();
  app.get("/hello", (req, res) => res.json({ message: greeting(req.query.name) }));
  app.get("/health", (_req, res) => res.json({ status: "ok" }));
  return app;
}
