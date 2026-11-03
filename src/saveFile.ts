function plainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A progress export this app can apply without wiping data by accident. */
export function isSaveFile(data: unknown): data is Record<string, unknown> {
  if (!plainObject(data)) return false;
  if (!("progress" in data) && !("learning" in data) && !("loot" in data)) return false;
  if ("progress" in data && !plainObject(data.progress)) return false;
  if ("learning" in data && !plainObject(data.learning)) return false;
  if ("loot" in data && !Array.isArray(data.loot)) return false;
  return true;
}
