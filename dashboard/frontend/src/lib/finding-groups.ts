export interface IssueSignature {
  severity: string;
  module: string;
  rule: string;
  message?: string | null;
}

export interface IssueGroup<T> {
  key: string;
  representative: T;
  occurrences: T[];
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function normalize(value: string | null | undefined): string {
  return (value ?? "").trim().replace(/\s+/g, " ").toLowerCase();
}

/** Group the same reported issue across files while preserving every occurrence. */
export function groupIssues<T extends IssueSignature>(items: readonly T[]): IssueGroup<T>[] {
  const groups = new Map<string, IssueGroup<T>>();

  for (const item of items) {
    const key = JSON.stringify([
      normalize(item.severity),
      normalize(item.module),
      normalize(item.rule),
      normalize(item.message),
    ]);
    const group = groups.get(key);
    if (group) {
      group.occurrences.push(item);
    } else {
      groups.set(key, { key, representative: item, occurrences: [item] });
    }
  }

  return [...groups.values()].sort((left, right) => {
    const leftSeverity = SEVERITY_ORDER.indexOf(normalize(left.representative.severity));
    const rightSeverity = SEVERITY_ORDER.indexOf(normalize(right.representative.severity));
    const severityDifference =
      (leftSeverity === -1 ? SEVERITY_ORDER.length : leftSeverity) -
      (rightSeverity === -1 ? SEVERITY_ORDER.length : rightSeverity);
    if (severityDifference) return severityDifference;

    const countDifference = right.occurrences.length - left.occurrences.length;
    if (countDifference) return countDifference;
    return left.representative.rule.localeCompare(right.representative.rule);
  });
}
