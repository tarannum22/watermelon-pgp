// Helpers for the core flows, written the way a user does them: through the pages.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { expect, type Page } from "@playwright/test";
import { BINARY, RUN_DIR } from "./env";

let counter = 0;
/** A name no other test uses, so tests don't depend on each other's data. */
export function unique(prefix: string): string {
  counter += 1;
  return `${prefix} ${Date.now().toString(36)}${counter}`;
}

/** Create a customer and return the URL of its page. */
export async function createCustomer(page: Page, name: string): Promise<string> {
  await page.goto("/customers");
  await page.getByLabel("Name").fill(name);
  await page.getByRole("button", { name: "Create customer" }).click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.getByRole("status")).toContainText(`Created customer ${name}.`);
  return new URL(page.url()).pathname;
}

/** Generate a key pair on the customer's page and return its fingerprint. */
export async function generateKey(page: Page, customerUrl: string, userId: string): Promise<string> {
  await page.goto(customerUrl);
  await page.getByLabel("User ID").fill(userId);
  await page.getByRole("button", { name: "Generate key pair" }).click();
  await expect(page.getByRole("status")).toContainText("Generated key");
  await page.getByRole("link", { name: userId.split(" <")[0], exact: true }).click();
  const fingerprint = await page.locator(".fpr-box button.copy").getAttribute("data-copy");
  expect(fingerprint).toMatch(/^[0-9A-F]{40}$/);
  return fingerprint!;
}

/** A fresh folder for a job's files. */
export function folder(name: string): string {
  const dir = path.join(RUN_DIR, "folders", name.replace(/\W+/g, "-"));
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Wait until `dir` holds a file whose name matches, and return its path. */
export async function waitForFile(dir: string, pattern: RegExp, timeout = 45_000): Promise<string> {
  let found: string | undefined;
  await expect
    .poll(
      () => {
        found = fs.existsSync(dir) ? fs.readdirSync(dir).find((f) => pattern.test(f)) : undefined;
        return found;
      },
      { timeout, intervals: [500] },
    )
    .toBeTruthy();
  return path.join(dir, found!);
}

/**
 * A partner's public key, made with the CLI in a separate data directory: as if the partner
 * had sent it to us. Returns the armored key.
 */
export function partnerPublicKey(userId: string): string {
  const dir = path.join(RUN_DIR, "partner", Date.now().toString(36));
  fs.mkdirSync(dir, { recursive: true });
  const env = { ...process.env, WATERMELON_DATA_DIR: dir, WATERMELON_LOG: "warn" };
  const run = (args: string[], input = "") =>
    execFileSync(BINARY, args, { env, input, encoding: "utf8", stdio: ["pipe", "pipe", "inherit"] });
  run(["init", "--passphrase-stdin"], "partner-password-123\n");
  run(["customer", "add", "Us"]);
  const fingerprint = run(["key", "gen", "--customer", "Us", "--uid", userId]).match(/[0-9A-F]{40}/)![0];
  return run(["key", "export", fingerprint]);
}

/**
 * Wait until htmx has wired up `selector`. After a boosted navigation htmx swaps the new page
 * in and then processes it; acting in between would bypass htmx. htmx marks elements it has
 * processed with an internal data property.
 */
export async function htmxReady(page: Page, selector: string): Promise<void> {
  await page.waitForFunction(
    (sel) => {
      const element = document.querySelector(sel) as (Element & { "htmx-internal-data"?: unknown }) | null;
      return !!element?.["htmx-internal-data"];
    },
    selector,
  );
}
