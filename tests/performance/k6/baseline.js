import { edgeOptions, edgeRequest } from "./profile-common.js";

export const options = {
  ...edgeOptions,
  scenarios: {
    warmup: { executor: "constant-vus", vus: 10, duration: "1m", exec: "edgeRequest" },
    measurement: { executor: "constant-vus", vus: 10, duration: "5m", startTime: "1m", exec: "edgeRequest" },
  },
};

export { edgeRequest };
