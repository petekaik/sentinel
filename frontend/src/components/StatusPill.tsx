/* RAG, and the word with it. Colour alone is never the message: an operator
   reading this on a phone in sunlight, or with a colour deficiency, must still
   be able to tell "cannot see it" (grey) from "it is fine" (green). Both
   vocabularies the API uses are accepted -- check verdicts are
   ok/warn/fail/unknown, incident severity is red/amber. */

const TONE: Record<string, { cls: string; word: string }> = {
  ok: { cls: "green", word: "OK" },
  warn: { cls: "amber", word: "WARN" },
  fail: { cls: "red", word: "FAIL" },
  unknown: { cls: "grey", word: "UNKNOWN" },
  green: { cls: "green", word: "GREEN" },
  amber: { cls: "amber", word: "AMBER" },
  red: { cls: "red", word: "RED" },
  grey: { cls: "grey", word: "GREY" },
};

export default function StatusPill({
  status,
  label,
}: {
  status: string | null | undefined;
  label?: string;
}) {
  const key = (status || "").toLowerCase();
  const tone = TONE[key] ?? { cls: "grey", word: status || "UNKNOWN" };
  return <span className={`pill ${tone.cls}`}>{label ?? tone.word}</span>;
}
