import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const port = process.env.SPONZEY_NEXTCLOUD_EDGE_PORT ?? "18080";
const endpoint = `http://127.0.0.1:${port}/status.php`;
const response = execFileSync(
  "curl",
  ["--fail", "--silent", "--show-error", "--max-time", "10", "-H", "Host: nextcloud.test", endpoint],
  { encoding: "utf8" },
);
const status = JSON.parse(response);
assert.equal(status.installed, true, "Nextcloud must be initialized behind Edge");
console.log(JSON.stringify({ status: "ok", endpoint: "/status.php", installed: status.installed }));
