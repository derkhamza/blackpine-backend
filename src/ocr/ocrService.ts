export interface OcrResult {
  rawText: string;
  amounts: number[];
  dates: string[];
  bestAmount: number | null;
  bestDate: string | null;
  confidence: number;
}

export async function extractFromReceipt(imageBuffer: Buffer): Promise<OcrResult> {
  console.log("[OCR] Sending to OCR.space...");

  const base64 = imageBuffer.toString("base64");
  const apiKey = process.env.OCR_SPACE_API_KEY || "";

  const formBody = new URLSearchParams({
    apikey: apiKey,
    base64Image: `data:image/jpeg;base64,${base64}`,
    language: "fre",
    isOverlayRequired: "false",
    detectOrientation: "true",
    scale: "true",
    OCREngine: "2",
  });

  const res = await fetch("https://api.ocr.space/parse/image", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formBody.toString(),
  });

  const data = await res.json();

  if (!data.ParsedResults || data.ParsedResults.length === 0) {
    console.log("[OCR] No results from API");
    return { rawText: "", amounts: [], dates: [], bestAmount: null, bestDate: null, confidence: 0 };
  }

  const text = data.ParsedResults[0].ParsedText || "";
  const confidence = data.ParsedResults[0].TextOverlay?.confidence || 70;

  console.log("[OCR] Text extracted, length:", text.length);
  console.log("[OCR] Preview:", text.substring(0, 200));

  const amounts = extractAmounts(text);
  const dates = extractDates(text);

  return {
    rawText: text,
    amounts,
    dates,
    bestAmount: pickBestAmount(amounts),
    bestDate: pickBestDate(dates),
    confidence,
  };
}

function extractAmounts(text: string): number[] {
  const amounts: number[] = [];

  const frenchPattern = /(\d[\d\s.]*),(\d{2})\b/g;
  let match;
  while ((match = frenchPattern.exec(text)) !== null) {
    const whole = match[1].replace(/[\s.]/g, "");
    const value = parseFloat(`${whole}.${match[2]}`);
    if (!isNaN(value) && value > 0 && value < 10000000) {
      amounts.push(value);
    }
  }

  const dotPattern = /(\d+)\.(\d{2})\b/g;
  while ((match = dotPattern.exec(text)) !== null) {
    const value = parseFloat(`${match[1]}.${match[2]}`);
    if (!isNaN(value) && value > 0 && value < 10000000 && !amounts.includes(value)) {
      amounts.push(value);
    }
  }

  const wholePattern = /(\d{2,7})\s*(?:MAD|DH|Dhs|dirhams?)/gi;
  while ((match = wholePattern.exec(text)) !== null) {
    const value = parseInt(match[1]);
    if (!isNaN(value) && value > 0 && !amounts.includes(value)) {
      amounts.push(value);
    }
  }

  return amounts.sort((a, b) => b - a);
}

function extractDates(text: string): string[] {
  const dates: string[] = [];
  const datePattern = /(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})/g;
  let match;
  while ((match = datePattern.exec(text)) !== null) {
    let day = parseInt(match[1]);
    let month = parseInt(match[2]);
    let year = parseInt(match[3]);
    if (year < 100) year += 2000;
    if (month >= 1 && month <= 12 && day >= 1 && day <= 31 && year >= 2020 && year <= 2030) {
      const iso = `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
      if (!dates.includes(iso)) dates.push(iso);
    }
  }
  return dates;
}

function pickBestAmount(amounts: number[]): number | null {
  return amounts.length > 0 ? amounts[0] : null;
}

function pickBestDate(dates: string[]): string | null {
  return dates.length > 0 ? dates.sort().reverse()[0] : null;
}