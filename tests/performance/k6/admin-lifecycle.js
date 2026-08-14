import http from "k6/http";
import { check, fail } from "k6";

const adminBaseUrl = "http://127.0.0.1:9443/api/v1";
const credential = open("/run/secrets/admin-credential.secret");
const currentConfig = open("/fixtures/edge-perf.toml");

function requireStatus(response, expectedStatus, step) {
  if (!check(response, { [`${step} returns ${expectedStatus}`]: (value) => value.status === expectedStatus })) {
    fail(`${step} did not complete`);
  }
}

export default function () {
  const setup = http.post(
    `${adminBaseUrl}/setup`,
    JSON.stringify({ password_hash: credential }),
    { headers: { "Content-Type": "application/json" } },
  );
  requireStatus(setup, 200, "setup");

  const login = http.post(
    `${adminBaseUrl}/login`,
    JSON.stringify({ password_hash: credential }),
    { headers: { "Content-Type": "application/json" } },
  );
  requireStatus(login, 200, "login");
  const session = login.cookies.sponzey_session?.[0]?.value;
  const csrfToken = JSON.parse(login.body).csrf_token;
  if (!session || !csrfToken) {
    fail("login did not create a session");
  }

  const authenticated = {
    headers: {
      "Content-Type": "text/plain",
      Cookie: `sponzey_session=${session}`,
    },
  };
  requireStatus(http.post(`${adminBaseUrl}/config/validate`, currentConfig, authenticated), 200, "validate");

  const mutation = {
    headers: {
      ...authenticated.headers,
      "X-CSRF-Token": csrfToken,
    },
  };
  requireStatus(http.post(`${adminBaseUrl}/config/apply`, currentConfig, mutation), 200, "apply");
  requireStatus(
    http.post(
      `${adminBaseUrl}/config/rollback`,
      JSON.stringify({ revision_id: "bootstrap-seed" }),
      {
        headers: {
          ...mutation.headers,
          "Content-Type": "application/json",
        },
      },
    ),
    200,
    "rollback",
  );
}
