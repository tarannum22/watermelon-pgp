// Shared by the config, the server script and the tests.
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));

export const PORT = Number(process.env.E2E_PORT ?? 18080);
export const BASE_URL = `http://127.0.0.1:${PORT}`;
export const PASSWORD = "e2e-admin-password";
/** Everything a run writes: database, job folders, the login state. Wiped at the start. */
export const RUN_DIR = path.resolve(here, "..", ".run");
export const DATA_DIR = path.join(RUN_DIR, "data");
/** The binary under test; build it first (`cargo build --features evaluation`). */
export const BINARY = path.resolve(
  here,
  "..",
  process.env.WATERMELON_BIN ?? path.join("..", "target", "debug", "watermelon"),
);
