import { edgeOptions, edgeRequest } from "./profile-common.js";

export const options = {
  ...edgeOptions,
  scenarios: {
    stress: {
      executor: "ramping-vus",
      startVUs: 1,
      stages: [
        { duration: "1m", target: 10 },
        { duration: "1m", target: 25 },
        { duration: "1m", target: 50 },
        { duration: "1m", target: 0 },
      ],
      exec: "edgeRequest",
    },
  },
};

export { edgeRequest };
