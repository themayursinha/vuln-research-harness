// Synthetic code-map fixture. Not a research target.
// function notIndexed() { return missing(); }

import { normalizePath } from "./path-utils.js";

const sample = `function fake() { return missing(); }`;

export function setAllowed(dirs) {
  return normalizePath(dirs);
}

const arrow = () => {
  return normalizePath("synthetic");
};
