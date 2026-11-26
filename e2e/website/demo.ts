// Started by playwright.website.config.ts: a demo installation in the release's Docker image,
// filled with made-up customers, keys, jobs and files through the CLI, then `serve`.
// Nothing outside the container is touched; the container and its volume go when it stops.
import { execFileSync, spawn } from "node:child_process";
import { CONTAINER, IMAGE, PASSWORD, PORT } from "./env.ts";

if (!/:\d+\.\d+\.\d+$/.test(IMAGE) && !process.env.WEBSITE_VERSION) {
  console.error("Set WEBSITE_IMAGE=ghcr.io/tarannum22/watermelon-pgp:X.Y.Z (or WEBSITE_VERSION for another tag).");
  process.exit(1);
}

const docker = (args: string[], input = "") =>
  execFileSync("docker", args, { input, encoding: "utf8", stdio: ["pipe", "pipe", "inherit"] });
const remove = () => execFileSync("docker", ["rm", "--force", "--volumes", CONTAINER], { stdio: "ignore" });
const QUIET = ["--env", "WATERMELONPGP_LOG=warn"];
const exec = (cmd: string[], input = "") => docker(["exec", "--interactive", ...QUIET, CONTAINER, ...cmd], input);
/** Our installation, the one the screenshots show. */
const ours = (...args: string[]) => exec(["watermelonpgp", ...args]);
/** The partners' side, in a data directory of its own: their keys and the files they send us. */
const partners = (...args: string[]) => exec(["watermelonpgp", "--data-dir", "/tmp/partners", ...args]);
const fingerprint = (output: string) => output.match(/[0-9A-F]{40}/)![0];
/** Write files into the container: name → content. */
const put = (dir: string, files: Record<string, string>) => {
  for (const [name, content] of Object.entries(files)) {
    exec(["sh", "-c", 'mkdir -p "$1" && cat > "$1/$2"', "sh", dir, name], content);
  }
};
/** `run-once` exits with 1 when a file failed, which the demo wants once. */
const runOnce = (job: string) => {
  try {
    ours("job", "run-once", "--settle", "0", job);
  } catch {
    // The failed file is part of the demo.
  }
};

remove();
docker([
  "run", "--detach", "--name", CONTAINER, "--publish", `127.0.0.1:${PORT}:8080`,
  // The job folders, writable by the image's user (uid 10001).
  "--tmpfs", "/srv/sftp:uid=10001,gid=10001,mode=0755",
  "--entrypoint", "sleep", IMAGE, "infinity",
]);
const stop = () => {
  remove();
  process.exit(0);
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);

exec(["watermelonpgp", "init", "--passphrase-stdin"], `${PASSWORD}\n`);
exec(["watermelonpgp", "--data-dir", "/tmp/partners", "init", "--passphrase-stdin"], `${PASSWORD}\n`);

// Customers and our own keys.
for (const customer of ["Alpine Outdoor GmbH", "Brightwave Retail", "Nordic Freight AB"]) {
  ours("customer", "add", customer);
}
const signing = fingerprint(ours("key", "gen", "--uid", "Example Logistics signing <pgp@logistics.example>"));
const inbound = fingerprint(
  ours("key", "gen", "--customer", "Nordic Freight AB", "--uid", "Inbound invoices <invoices@logistics.example>"),
);

// The partners' keys, as they would send them to us; Alpine replaced its 2024 key.
partners("customer", "add", "Partners");
const partnerKey = (uid: string) => fingerprint(partners("key", "gen", "--customer", "Partners", "--uid", uid));
const alpineOld = partnerKey("Alpine Outdoor EDI (2024) <edi@alpine-outdoor.example>");
partners("key", "revoke", alpineOld, "--reason", "superseded", "--comment", "replaced by the 2025 key");
const alpine = partnerKey("Alpine Outdoor EDI (2025) <edi@alpine-outdoor.example>");
const brightwave = partnerKey("Brightwave Retail Reports <reports@brightwave.example>");
const nordic = partnerKey("Nordic Freight Billing <billing@nordicfreight.example>");
const give = (key: string, customer: string) => {
  partners("key", "export", key, "--output", `/tmp/partners/${key}.asc`);
  ours("key", "import", "--customer", customer, `/tmp/partners/${key}.asc`);
};
give(alpineOld, "Alpine Outdoor GmbH");
give(alpine, "Alpine Outdoor GmbH");
give(brightwave, "Brightwave Retail");
give(nordic, "Nordic Freight AB");
// Nordic encrypts its invoices to our inbound key and signs them.
ours("key", "export", inbound, "--output", "/tmp/partners/inbound.asc");
partners("key", "import", "--customer", "Partners", "/tmp/partners/inbound.asc");

// Folders and jobs.
exec(["sh", "-c", "mkdir -p /srv/sftp/alpine/orders /srv/sftp/alpine/out /srv/sftp/brightwave/reports /srv/sftp/brightwave/out /srv/sftp/nordic/in /srv/sftp/nordic/import /srv/sftp/nordic/payments /srv/sftp/nordic/out /tmp/nordic-outbox /tmp/nordic-sent"]);
const encryptJob = (customer: string, name: string, dir: string, recipient: string, interval: string) =>
  ours("job", "add", "encrypt", "--customer", customer, "--name", name,
    "--input", `/srv/sftp/${dir}`, "--output", `/srv/sftp/${dir.split("/")[0]}/out`,
    "--recipient", recipient, "--sign-with", signing, "--interval", interval);
encryptJob("Brightwave Retail", "weekly-reports", "brightwave/reports", brightwave, "60");
encryptJob("Alpine Outdoor GmbH", "purchase-orders", "alpine/orders", alpine, "30");
encryptJob("Nordic Freight AB", "payment-advice", "nordic/payments", nordic, "30");
ours("job", "add", "decrypt", "--customer", "Nordic Freight AB", "--name", "inbound-invoices",
  "--input", "/srv/sftp/nordic/in", "--output", "/srv/sftp/nordic/import",
  "--key", inbound, "--verify-with", nordic, "--verify", "require", "--interval", "5");
partners("job", "add", "encrypt", "--customer", "Partners", "--name", "invoices",
  "--input", "/tmp/nordic-outbox", "--output", "/srv/sftp/nordic/in", "--processed", "/tmp/nordic-sent",
  "--recipient", inbound, "--sign-with", nordic);

// Files: made up, but shaped like the real thing.
const csv = (rows: number, seed: number) =>
  "id;date;amount;currency\n" +
  Array.from({ length: rows }, (_, i) => `${seed + i};2026-11-${String((i % 28) + 1).padStart(2, "0")};${((seed * 7 + i * 13) % 900) + 100}.00;EUR`).join("\n") +
  "\n";
const pdf = (title: string) => `%PDF-1.7\n% ${title}\n${"x".repeat(4000)}\n%%EOF\n`;
put("/srv/sftp/brightwave/reports", Object.fromEntries([44, 45, 46, 47].map((w) => [`sales-week-${w}.pdf`, pdf(`Sales week ${w}`)])));
put("/srv/sftp/alpine/orders", { "PO-2026-1187.csv": csv(40, 1187), "PO-2026-1188.csv": csv(25, 1188), "PO-2026-1189.csv": csv(60, 1189) });
put("/srv/sftp/nordic/payments", { "payment-advice-2026-11-24.csv": csv(18, 900), "payment-advice-2026-11-25.csv": csv(22, 940) });
put("/tmp/nordic-outbox", { "invoice-4471.csv": csv(12, 4471), "invoice-4472.csv": csv(9, 4472), "invoice-4473.csv": csv(15, 4473) });

partners("job", "run-once", "--settle", "0", "invoices");
// A file that isn't OpenPGP at all: the failed file on the job's page.
put("/srv/sftp/nordic/in", { "invoice-4474.csv.pgp": "this upload was cut short\n".repeat(23) });
for (const job of ["purchase-orders", "payment-advice", "inbound-invoices", "weekly-reports"]) {
  runOnce(job);
}

// Serve until Playwright stops us.
const server = spawn("docker", ["exec", ...QUIET, CONTAINER, "watermelonpgp", "serve"], { stdio: "inherit" });
server.on("exit", stop);
