import fs from "node:fs";
import path from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { createCustomer, folder, generateKey, unique, waitForFile } from "../support/app";

/** Fill in and submit the new-job form. */
async function createJob(
  page: Page,
  options: { customer: string; name: string; kind: "Encrypt" | "Decrypt"; input: string; output: string; key: string },
) {
  await page.goto("/jobs/new");
  await page.getByLabel("Customer").selectOption({ label: options.customer });
  await page.getByLabel("Name", { exact: true }).fill(options.name);
  await page.getByText(options.kind, { exact: true }).click();
  await page.getByLabel("Input folder (watched)").fill(options.input);
  await page.getByLabel("Output folder").fill(options.output);
  await page.getByLabel("Check every (seconds)").fill("5");
  const keys = page.locator(options.kind === "Encrypt" ? ".encrypt-only" : ".decrypt-only");
  await keys.locator(".check", { hasText: options.key }).first().getByRole("checkbox").check();
  await page.getByRole("button", { name: "Create job" }).click();
  await expect(page.getByRole("status")).toContainText(`Created job ${options.name}. It is running.`);
  await expect(page.locator("#live .pill")).toHaveText("running");
}

test("encrypt a dropped file, decrypt it again, and retry a failure", async ({ page }) => {
  test.slow();
  const customer = unique("Roundtrip");
  const customerUrl = await createCustomer(page, customer);
  await generateKey(page, customerUrl, "Roundtrip Key <roundtrip@example.com>");

  const outbox = folder(`${customer} outbox`);
  const upload = folder(`${customer} upload`);
  const decrypted = folder(`${customer} decrypted`);

  // Encrypt: a file dropped into the outbox comes out encrypted in the upload folder.
  await createJob(page, { customer, name: "daily-orders", kind: "Encrypt", input: outbox, output: upload, key: "Roundtrip Key" });
  const original = "order,quantity\nwatermelon,12\n";
  fs.writeFileSync(path.join(outbox, "orders.csv"), original);
  const encrypted = await waitForFile(upload, /^orders\.csv\.pgp$/);
  expect(fs.readFileSync(encrypted)).not.toContain(Buffer.from("watermelon"));
  await waitForFile(path.join(outbox, "processed"), /^orders\.csv$/);

  // The dashboard and the audit log know about it.
  await page.goto("/");
  await expect(page.locator(".stat", { hasText: "Files processed" }).locator(".stat-value")).not.toHaveText("0");
  await page.goto("/audit?q=orders.csv");
  await expect(page.locator("table.audit")).toContainText("file.processed");

  // Decrypt: the upload folder is the next job's input; the original comes back.
  await createJob(page, { customer, name: "check-orders", kind: "Decrypt", input: upload, output: decrypted, key: "Roundtrip Key" });
  const roundtrip = await waitForFile(decrypted, /^orders\.csv$/);
  expect(fs.readFileSync(roundtrip, "utf8")).toBe(original);

  // A file that isn't OpenPGP fails, shows on the job page, and can be retried.
  fs.writeFileSync(path.join(upload, "garbage.pgp"), "not encrypted at all");
  await waitForFile(path.join(upload, "failed"), /^garbage\.pgp$/);
  const failed = page.locator("#live tr", { hasText: "garbage.pgp" });
  await expect(failed).toBeVisible({ timeout: 15_000 }); // the status panel refreshes itself
  await failed.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("status")).toContainText("Moved garbage.pgp back to the input folder");
});

test("a job can be disabled and enabled again", async ({ page }) => {
  const customer = unique("Toggle");
  const customerUrl = await createCustomer(page, customer);
  await generateKey(page, customerUrl, "Toggle Key <toggle@example.com>");
  await createJob(page, {
    customer,
    name: "toggle-job",
    kind: "Encrypt",
    input: folder(`${customer} in`),
    output: folder(`${customer} out`),
    key: "Toggle Key",
  });

  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.locator("#live .pill")).toHaveText("disabled");
  await page.getByRole("button", { name: "Enable" }).click();
  await expect(page.locator("#live .pill")).toHaveText("running");
});

test("the job form explains what's wrong and keeps the input", async ({ page }) => {
  const customer = unique("Mistakes");
  await createCustomer(page, customer);
  await page.goto("/jobs/new");
  await page.getByLabel("Customer").selectOption({ label: customer });
  await page.getByLabel("Name", { exact: true }).fill("broken-job");
  await page.getByLabel("Input folder (watched)").fill("/does/not/exist");
  await page.getByLabel("Output folder").fill("/does/not/exist/either");
  await page.getByRole("button", { name: "Create job" }).click();
  await expect(page.getByRole("alert")).toContainText("The job was not saved");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("broken-job");
});
