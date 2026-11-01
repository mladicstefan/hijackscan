// Display helpers. Pure functions: same input, same text.

const int = new Intl.NumberFormat("en");

export const fmtInt = (n: number | null | undefined) => (n === null || n === undefined ? "–" : int.format(n));

export const fmtScore = (n: number | null | undefined) => (n === null || n === undefined ? "–" : n.toFixed(1));

/** 0.1234 → "12%"; a share of null (nothing to divide by) → "–". */
export const fmtShare = (x: number | null | undefined) => (x === null || x === undefined ? "–" : `${Math.round(x * 100)}%`);

export const pct = (part: number, total: number) => (total ? `${Math.round((100 * part) / total)}%` : "–");

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "–";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }) + " UTC";
}

/** "domain-owner + dns-host" → "domain owner + DNS host": who has to act. */
export const fmtOwner = (owner: string) =>
  owner
    .split(" + ")
    .map((o) => ({ "domain-owner": "domain owner", "dns-host": "DNS host", "hosting-provider": "hosting provider" })[o] ?? o)
    .join(" + ");
