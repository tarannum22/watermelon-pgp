// Started by Playwright before the tests: a fresh data directory and `watermelonpgp serve`.
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import { BINARY, DATA_DIR, PASSWORD, PORT, RUN_DIR } from "./env.ts";

if (!fs.existsSync(BINARY)) {
  console.error(`No binary at ${BINARY}. Build it with: cargo build`);
  process.exit(1);
}
fs.rmSync(RUN_DIR, { recursive: true, force: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

const env = { ...process.env, WATERMELONPGP_DATA_DIR: DATA_DIR, WATERMELONPGP_LOG: "warn" };
execFileSync(BINARY, ["init", "--passphrase-stdin"], { env, input: `${PASSWORD}\n`, stdio: ["pipe", "ignore", "inherit"] });

const server = spawn(BINARY, ["serve", "--bind", `127.0.0.1:${PORT}`], { env, stdio: "inherit" });
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => server.kill("SIGTERM"));
}
server.on("exit", (code) => process.exit(code ?? 0));
