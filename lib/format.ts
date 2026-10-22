/**
 * Formats a duration in seconds for display. Sub-second values are shown in milliseconds so a fast response
 * never reads as "0.0 s": 52 ms / 2.05 s / 3 m 05 s. Unknown values (null) read "n/a", never 0.
 */
export function formatDuration(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || Number.isNaN(sec)) return 'n/a';
  if (sec < 1) return `${Math.round(sec * 1000)} ms`;
  if (sec < 60) return `${sec.toFixed(2)} s`;
  const m = Math.floor(sec / 60);
  return `${m} m ${String(Math.round(sec - m * 60)).padStart(2, '0')} s`;
}
