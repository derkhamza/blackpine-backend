import express from "express";
import cors from "cors";
import { initDatabase } from "./db/database";
import authRoutes from "./routes/auth";
import syncRoutes from "./routes/sync";
import { authRequired } from "./middleware/auth";

const PORT = process.env.PORT || 3001;

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: "10mb" }));

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "blackpine-backend" });
});

// Public routes
app.use("/auth", authRoutes);

// Protected routes
app.use("/sync", authRequired, syncRoutes);

// Initialize database and start
initDatabase();

app.listen(PORT, () => {
  console.log(`\n[SERVER] Blackpine backend running on http://localhost:${PORT}`);
  console.log(`[SERVER] Health check: http://localhost:${PORT}/health\n`);
});