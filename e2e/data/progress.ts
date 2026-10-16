export const STORAGE_KEY = "hacklab.progress.v1";

/** Storage contents the app must survive, with the progress it should recover. */
export const CORRUPTED_STORAGE: {
  name: string;
  raw: string;
  /** Cleared-level count per lab id after loading. */
  expected: Record<string, number>;
}[] = [
  { name: "invalid JSON", raw: "{bad", expected: { xss: 0, sqli: 0 } },
  { name: "wrong top-level type", raw: "[1,2,3]", expected: { xss: 0, sqli: 0 } },
  {
    name: "malformed entries",
    raw: JSON.stringify({ xss: "oops", sqli: [1, 99, "x", 1], path: null }),
    expected: { xss: 0, sqli: 1, path: 0 },
  },
];
