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
app.use("/ocr-proxy", ocrProxyRouter);

const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "blackpine-backend" });
});

app.use("/auth", authRoutes);
app.use("/reset", resetRoutes);
app.use("/verify", verifyRouter);
app.use("/subscription", subscriptionRouter);
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