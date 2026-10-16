/** `Disgruntled operator` becomes `disgruntled-operator` (the persona's symbolic name). */
export function symbolicNameFromName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60)
}
