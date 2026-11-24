import fs from "node:fs";
import { expect, test } from "@playwright/test";
import { createCustomer, generateKey, partnerPublicKey, unique } from "../support/app";

test("generate a key pair and download its public key", async ({ page }) => {
  const customer = unique("Alpine Outdoor");
  const customerUrl = await createCustomer(page, customer);
  const fingerprint = await generateKey(page, customerUrl, "Alpine Exports <exports@alpine.example>");

  // The key's own page.
  await expect(page.getByRole("heading", { level: 1, name: "Alpine Exports" })).toBeVisible();
  await expect(page.locator(".fpr-box")).toContainText(fingerprint.slice(0, 4));
  await expect(page.getByText("Key pair: we hold the secret key.")).toBeVisible();

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Download public key (.asc)" }).click(),
  ]);
  const armored = fs.readFileSync((await download.path())!, "utf8");
  expect(armored).toContain("-----BEGIN PGP PUBLIC KEY BLOCK-----");
  expect(armored).not.toContain("PRIVATE KEY");

  // It's listed with the customer's keys, and in the key list.
  await page.goto("/keys?show=pairs");
  const row = page.locator(".key-row", { hasText: "exports@alpine.example" });
  await expect(row).toContainText("key pair");
  await expect(row.getByRole("link", { name: customer })).toBeVisible();
});

test("import a partner's public key by pasting it", async ({ page }) => {
  const customerUrl = await createCustomer(page, unique("Brightwave Retail"));
  const armored = partnerPublicKey("Brightwave SFTP <sftp@brightwave.example>");

  await page.goto(customerUrl);
  await page.getByLabel("…or paste an armored key").fill(armored);
  await page.getByRole("button", { name: "Import" }).click();
  await expect(page.getByRole("status")).toContainText("Imported or updated Brightwave SFTP");

  const row = page.locator(".key-row", { hasText: "sftp@brightwave.example" });
  await expect(row).toContainText("public");
  await expect(row).not.toContainText("key pair");

  // The key list's filters find it.
  await page.goto("/keys");
  await page.getByRole("link", { name: /^Public only/ }).click();
  await expect(page.locator(".key-row", { hasText: "sftp@brightwave.example" })).toBeVisible();
  await page.getByRole("searchbox", { name: "Search keys" }).fill("brightwave.example");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.locator(".key-row")).toHaveCount(1);
});

test("revoking needs confirmation, then marks the key revoked", async ({ page }) => {
  const customerUrl = await createCustomer(page, unique("Nordic Freight"));
  await generateKey(page, customerUrl, "Nordic Old <old@nordic.example>");

  // The browser refuses the form until the box is ticked.
  await page.getByRole("button", { name: "Revoke key" }).click();
  await expect(page.locator(".page-head .pill")).toHaveText("valid");

  await page.getByLabel("Reason").selectOption("retired");
  await page.getByLabel("Revoke this key permanently").check();
  await page.getByRole("button", { name: "Revoke key" }).click();
  await expect(page.getByRole("status")).toContainText("Revoked key");
  await expect(page.locator(".page-head .pill")).toHaveText("revoked");

  await page.goto("/keys?show=revoked");
  await expect(page.locator(".key-row", { hasText: "old@nordic.example" })).toBeVisible();
});
