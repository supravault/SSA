/**
 * Get current ISO timestamp
 */
export function getIsoTimestamp(): string {
  return new Date().toISOString();
}

/**
 * Add days to a date and return ISO string
 */
export function addDays(isoDate: string, days: number): string {
  const date = new Date(isoDate);
  date.setDate(date.getDate() + days);
  return date.toISOString();
}

