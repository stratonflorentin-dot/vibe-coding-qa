import express from "express";
import { exec } from "child_process";
import fs from "fs";
const app = express();

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.cookie("session", token);
  next();
});

app.get("/debug/info", (req, res) => {
  res.json({ env: process.env, config: require("./config") });
});

app.post("/upload", (req, res) => {
  const path = "./uploads/" + req.query.filename;
  fs.writeFileSync(path, req.body);
  res.send("ok");
});

app.get("/fetch", async (req, res) => {
  const data = await fetch(req.query.url);
  res.send(await data.text());
});

app.post("/run", (req, res) => {
  exec(req.body.command, (err, stdout) => res.send(stdout));
});

app.get("/users/:id", (req, res) => {
  const q = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(q);
});

app.listen(3000);
