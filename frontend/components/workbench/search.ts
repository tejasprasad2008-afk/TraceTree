export interface SearchToken {
  field: string;
  value: string;
  negated: boolean;
}

export interface ParsedQuery {
  tokens: SearchToken[];
  freeText: string;
}

export const HTTPQL_FIELDS = ["verdict", "type", "file", "sha256", "after", "before", "size"] as const;

export const HTTPQL_COMPLETIONS: Record<string, string[]> = {
  verdict: ["danger", "caution", "safe", "pending"],
  type: ["pip", "npm", "dmg", "exe", "zip"],
};

const FIELD_PATTERN = new RegExp(
  `(-?)(${HTTPQL_FIELDS.join("|")}):([^\\s]+)`,
  "g"
);

export function parseQuery(raw: string): ParsedQuery {
  const tokens: SearchToken[] = [];
  let remainder = raw;

  FIELD_PATTERN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = FIELD_PATTERN.exec(raw)) !== null) {
    tokens.push({
      negated: m[1] === "-",
      field: m[2],
      value: m[3],
    });
    remainder = remainder.replace(m[0], "");
  }

  const freeText = remainder.trim();
  return { tokens, freeText };
}

export function matchRow<T extends Record<string, any>>(
  row: T,
  query: ParsedQuery,
  fieldMap: Record<string, keyof T>
): boolean {
  for (const tok of query.tokens) {
    const rowKey = fieldMap[tok.field];
    if (!rowKey) continue;
    const rowVal = String(row[rowKey] ?? "").toLowerCase();
    const tokVal = tok.value.toLowerCase().replace(/\*/g, ".*");
    const regex = new RegExp(`^${tokVal}$`);
    const matches = regex.test(rowVal);
    if (tok.negated && matches) return false;
    if (!tok.negated && !matches) return false;
  }

  if (query.freeText) {
    const ft = query.freeText.toLowerCase();
    const anyMatch = Object.values(row).some((v) =>
      String(v ?? "").toLowerCase().includes(ft)
    );
    if (!anyMatch) return false;
  }

  return true;
}
