import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const read = (filename) => readFileSync(path.join(root, filename), "utf8");

test("primary testing documentation distinguishes source and release performance boundaries", () => {
  const testing = read("docs/testing.md");
  const english = read("README.md");
  const korean = read("README.ko.md");
  for (const source of [testing, english, korean]) {
    assert.match(source, /node tests\/performance\/bin\/run\.mjs smoke/);
    assert.match(source, /edge-perf/);
    assert.match(source, /127\.0\.0\.1:3000/);
  }
  assert.match(testing, /node tests\/performance\/bin\/run\.mjs baseline/);
  assert.match(testing, /node tests\/performance\/bin\/run\.mjs stress/);
  assert.match(testing, /node tests\/performance\/bin\/run\.mjs soak/);
  assert.match(testing, /7,200-second memory\/release evidence/);
  assert.doesNotMatch(testing, /Admin.*0\.0\.0\.0/);
});
