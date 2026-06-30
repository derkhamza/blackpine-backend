/**
 * Normalize text for accent- and case-insensitive medication search.
 * Used by BOTH the import script (to build the `search` column) and the search
 * endpoint (to normalize the query) so they always match.
 */
export function normalizeText(s: string): string {
  return (s ?? "")
    .toString()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "") // strip diacritics (combining marks)
    .replace(/[^a-z0-9 ]/g, " ")     // keep alphanumerics + spaces
    .replace(/\s+/g, " ")
    .trim();
}
