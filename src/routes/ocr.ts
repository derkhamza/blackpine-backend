import { Router, Request, Response } from "express";
import { extractFromReceipt } from "../ocr/ocrService";

const router = Router();

router.post("/extract", async (req: Request, res: Response) => {
  try {
    const { imageBase64 } = req.body;

    if (!imageBase64) {
      return res.status(400).json({ error: "Aucune image reçue" });
    }

    console.log(`[OCR] Received base64 image, length: ${(imageBase64.length / 1024).toFixed(0)}KB`);

    const buffer = Buffer.from(imageBase64, "base64");
    const result = await extractFromReceipt(buffer);

    return res.json({
      success: true,
      amounts: result.amounts,
      dates: result.dates,
      bestAmount: result.bestAmount,
      bestDate: result.bestDate,
      confidence: result.confidence,
      rawTextPreview: result.rawText.substring(0, 300),
    });
  } catch (err: any) {
    console.error("[OCR] Extraction failed:", err.message);
    return res.status(500).json({ error: "Erreur d'extraction: " + err.message });
  }
});

export default router;