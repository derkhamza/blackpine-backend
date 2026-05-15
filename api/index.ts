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
import { subscriptionRequired } from "../src/middleware/subscription";
import ocrProxyRouter from "../src/routes/ocrProxy";
import inviteRoutes from "../src/routes/invite";
import cabinetRoutes from "../src/routes/cabinet";
import { rateLimit } from "../src/middleware/rateLimit";

const app = express();

app.use(cors());
app.use(express.json({ limit: "20mb" }));

app.use("/auth", rateLimit(10, 15 * 60 * 1000), authRoutes);
app.use("/reset", rateLimit(5, 15 * 60 * 1000), resetRoutes);
app.use("/verify", rateLimit(5, 10 * 60 * 1000), verifyRouter);
app.use("/subscription", rateLimit(10, 15 * 60 * 1000), subscriptionRouter);
app.use("/ocr-proxy", ocrProxyRouter);

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "blackpine-backend" });
});

app.use("/sync", authRequired, subscriptionRequired, syncRoutes);
app.use("/ocr", authRequired, ocrRoutes);
app.use("/invite", rateLimit(10, 15 * 60 * 1000), inviteRoutes);
app.use("/cabinet", cabinetRoutes);

let dbInitialized = false;

const handler = async (req: any, res: any) => {
  if (!dbInitialized) {
    await initDatabase();
    dbInitialized = true;
  }
  return app(req, res);
};

export default handler;
