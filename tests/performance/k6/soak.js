import { edgeOptions, edgeRequest } from "./profile-common.js";

export const options = {
  ...edgeOptions,
  scenarios: {
    soak: { executor: "constant-vus", vus: 10, duration: "30m", exec: "edgeRequest" },
  },
};

export { edgeRequest };
