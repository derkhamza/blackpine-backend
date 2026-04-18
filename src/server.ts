import express from "express";
import cors from "cors";
import { initDatabase } from "./db/database";
import authRoutes from "./routes/auth";
import syncRoutes from "./routes/sync";
import { authRequired } from "./middleware/auth";
import ocrRoutes from "./routes/ocr";

const PORT = process.env.PORT || 3001;

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: "20mb" }));

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "blackpine-backend" });
});

// Public routes
app.use("/auth", authRoutes);

// Protected routes
app.use("/sync", authRequired, syncRoutes);
app.use("/ocr", authRequired, ocrRoutes);

// Initialize database and start
initDatabase();

app.listen(Number(PORT), "0.0.0.0", () => {
  console.log(`\n[SERVER] Blackpine backend running on port ${PORT}`);
});