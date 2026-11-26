import type { CertificateRecord } from "./model";
export interface Interval {
  start: number;
  end: number;
}
export interface CoverageStudy {
  name: string;
  from: string;
  to: string;
  certificateCount: number;
  covered: Interval[];
  gaps: Interval[];
}

/** Union declared intervals for one exact SAN entry. This is not TLS validation. */
export function studyCoverage(
  records: CertificateRecord[],
  name: string,
  from: Date,
  to: Date,
): CoverageStudy {
  const low = from.getTime(),
    high = to.getTime();
  if (!Number.isFinite(low) || !Number.isFinite(high) || low >= high)
    throw new Error("Coverage study needs an increasing, finite time range.");
  const matching = records.filter((cert) =>
    cert.dnsNames.some((dns) => dns.toLowerCase() === name.toLowerCase()),
  );
  const intervals = matching
    .map((cert) => ({
      start: Math.max(low, Date.parse(cert.notBefore)),
      end: Math.min(high, Date.parse(cert.notAfter)),
    }))
    .filter(
      (i) =>
        Number.isFinite(i.start) && Number.isFinite(i.end) && i.start <= i.end,
    )
    .sort((a, b) => a.start - b.start || a.end - b.end);
  const covered: Interval[] = [];
  for (const interval of intervals) {
    const last = covered[covered.length - 1];
    if (last && interval.start <= last.end)
      last.end = Math.max(last.end, interval.end);
    else covered.push({ ...interval });
  }
  const gaps: Interval[] = [];
  let cursor = low;
  for (const interval of covered) {
    if (interval.start > cursor)
      gaps.push({ start: cursor, end: interval.start });
    cursor = Math.max(cursor, interval.end);
  }
  if (cursor < high) gaps.push({ start: cursor, end: high });
  return {
    name,
    from: from.toISOString(),
    to: to.toISOString(),
    certificateCount: matching.length,
    covered,
    gaps,
  };
}
