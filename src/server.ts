import express from "express";
import cors from "cors";
import { initDatabase } from "./db/database";
import authRoutes from "./routes/auth";
import syncRoutes from "./routes/sync";
import ocrRoutes from "./routes/ocr";
import { authRequired } from "./middleware/auth";
import "dotenv/config";
import resetRoutes from "./routes/reset";

const PORT = process.env.PORT || 3001;

const app = express();

app.use(cors());
app.use(express.json({ limit: "20mb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "blackpine-backend" });
});

app.use("/auth", authRoutes);
app.use("/reset", resetRoutes);
app.use("/sync", authRequired, syncRoutes);
app.use("/ocr", authRequired, ocrRoutes);

async function start() {
  await initDatabase();

  app.listen(Number(PORT), "0.0.0.0", () => {
    console.log(`\n[SERVER] Blackpine backend running on port ${PORT}`);
    console.log(`[SERVER] Health check: http://localhost:${PORT}/health\n`);
  });
}

start().catch((err) => {
  console.error("[SERVER] Failed to start:", err);
  process.exit(1);
});