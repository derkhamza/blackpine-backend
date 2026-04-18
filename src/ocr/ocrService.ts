import Tesseract from "tesseract.js";

export interface OcrResult {
  rawText: string;
  amounts: number[];
  dates: string[];
  bestAmount: number | null;
  bestDate: string | null;
  confidence: number;
}

/**
 * Runs OCR on an image buffer and extracts amounts and dates.
 * Uses French language model for better accuracy with Moroccan receipts.
 */
export async function extractFromReceipt(imageBuffer: Buffer): Promise<OcrResult> {
  console.log("[OCR] Starting text extraction...");

  const {
    data: { text, confidence },
  } = await Tesseract.recognize(imageBuffer, "fra", {
    logger: (m) => {
      if (m.status === "recognizing text") {
        console.log(`[OCR] Progress: ${Math.round(m.progress * 100)}%`);
      }
    },
  });

  console.log("[OCR] Raw text extracted, confidence:", confidence);
  console.log("[OCR] Text:", text.substring(0, 200));

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

/**
 * Extracts numeric amounts from OCR text.
 * Handles formats: 1234.56, 1234,56, 1 234,56, 1.234,56
 */
function extractAmounts(text: string): number[] {
  const amounts: number[] = [];

  // Pattern 1: numbers with comma as decimal separator (French style)
  // e.g., "1 234,56" or "1234,56" or "234,00"
  const frenchPattern = /(\d[\d\s.]*),(\d{2})\b/g;
  let match;
  while ((match = frenchPattern.exec(text)) !== null) {
    const whole = match[1].replace(/[\s.]/g, "");
    const decimal = match[2];
    const value = parseFloat(`${whole}.${decimal}`);
    if (!isNaN(value) && value > 0 && value < 10000000) {
      amounts.push(value);
    }
  }

  // Pattern 2: numbers with dot as decimal separator
  // e.g., "1234.56"
  const dotPattern = /(\d+)\.(\d{2})\b/g;
  while ((match = dotPattern.exec(text)) !== null) {
    const value = parseFloat(`${match[1]}.${match[2]}`);
    if (!isNaN(value) && value > 0 && value < 10000000) {
      // Avoid duplicates
      if (!amounts.includes(value)) {
        amounts.push(value);
      }
    }
  }

  // Pattern 3: whole numbers that look like prices (near keywords)
  const wholePattern = /(\d{2,7})\s*(?:MAD|DH|Dhs|dirhams?)/gi;
  while ((match = wholePattern.exec(text)) !== null) {
    const value = parseInt(match[1]);
    if (!isNaN(value) && value > 0 && !amounts.includes(value)) {
      amounts.push(value);
    }
  }

  return amounts.sort((a, b) => b - a); // largest first
}

/**
 * Extracts dates from OCR text.
 * Handles formats: DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY
 */
function extractDates(text: string): string[] {
  const dates: string[] = [];
  const datePattern = /(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})/g;
  let match;

  while ((match = datePattern.exec(text)) !== null) {
    let day = parseInt(match[1]);
    let month = parseInt(match[2]);
    let year = parseInt(match[3]);

    // Handle 2-digit years
    if (year < 100) year += 2000;

    // Basic validation
    if (month >= 1 && month <= 12 && day >= 1 && day <= 31 && year >= 2020 && year <= 2030) {
      const iso = `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
      if (!dates.includes(iso)) {
        dates.push(iso);
      }
    }
  }

  return dates;
}

/**
 * Picks the most likely total amount from extracted amounts.
 * Heuristic: the largest amount is usually the total.
 */
function pickBestAmount(amounts: number[]): number | null {
  if (amounts.length === 0) return null;
  return amounts[0]; // Already sorted largest first
}

/**
 * Picks the most likely receipt date.
 * Heuristic: the most recent date is usually the transaction date.
 */
function pickBestDate(dates: string[]): string | null {
  if (dates.length === 0) return null;
  return dates.sort().reverse()[0]; // Most recent first
}