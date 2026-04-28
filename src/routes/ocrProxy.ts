import { Router } from "express";

const router = Router();

router.post("/extract", async (req, res) => {
  try {
    const { base64Image } = req.body;
    if (!base64Image) return res.status(400).json({ error: "Image requise" });

    const apiKey = process.env.OCR_SPACE_API_KEY;
    if (!apiKey) return res.status(500).json({ error: "OCR not configured" });

    const formBody = new URLSearchParams({
      apikey: apiKey,
      base64Image,
      language: "fre",
      isOverlayRequired: "false",
      detectOrientation: "true",
      scale: "true",
      OCREngine: "2",
    });

    const ocrRes = await fetch("https://api.ocr.space/parse/image", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formBody.toString(),
    });

    const data = await ocrRes.json();
    res.json(data);
  } catch (err: any) {
    console.error("[OCR-PROXY]", err.message);
    res.status(500).json({ error: err.message });
  }
});

export default router;