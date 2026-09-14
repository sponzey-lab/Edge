import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const port = process.env.SPONZEY_NEXTCLOUD_EDGE_PORT ?? "18080";
const endpoint = `http://127.0.0.1:${port}/`;
const response = execFileSync(
  "curl",
  ["--head", "--silent", "--show-error", "--max-time", "10", endpoint],
  { encoding: "utf8" },
);
assert.match(response, /HTTP\/1\.1 302 Found/);
assert.match(response, new RegExp(`Location: http://127\\.0\\.0\\.1:${port}/login`));
console.log(JSON.stringify({ status: "ok", endpoint: "/", login_redirect: `/login` }));
