import "dotenv/config";
import express from "express";
import cors from "cors";
import { initDatabase } from "../src/db/database";
import authRoutes from "../src/routes/auth";
import syncRoutes from "../src/routes/sync";
import ocrRoutes from "../src/routes/ocr";
import resetRoutes from "../src/routes/reset";
import verifyRouter from "../src/routes/verify";
import subscriptionRouter from "../src/routes/subscription";
import { authRequired } from "../src/middleware/auth";
import ocrProxyRouter from "../src/routes/ocrProxy";
import { rateLimit } from "../src/middleware/rateLimit";
const app = express();
// Before route definitions, add rate-limited routes:
app.use("/auth", rateLimit(10, 15 * 60 * 1000), authRoutes);          // 10 attempts per 15 min
app.use("/reset", rateLimit(5, 15 * 60 * 1000), resetRoutes);          // 5 attempts per 15 min
app.use("/verify", rateLimit(5, 10 * 60 * 1000), verifyRouter);        // 5 attempts per 10 min
app.use("/subscription", rateLimit(10, 15 * 60 * 1000), subscriptionRouter);
app.use("/ocr-proxy", ocrProxyRouter);


app.use(cors());
app.use(express.json({ limit: "20mb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "blackpine-backend" });
});

app.use("/sync", authRequired, syncRoutes);
app.use("/ocr", authRequired, ocrRoutes);

let dbInitialized = false;

const handler = async (req: any, res: any) => {
  if (!dbInitialized) {
    await initDatabase();
    dbInitialized = true;
  }
  return app(req, res);
};

export default handler;