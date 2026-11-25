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

test("generate a key pair from the Keys page, for a chosen customer", async ({ page }) => {
  const customer = unique("Keys Page");
  await createCustomer(page, customer);

  await page.goto("/keys");
  await page.getByRole("button", { name: "Generate key pair" }).click();
  const dialog = page.getByRole("dialog", { name: "Generate a key pair" });
  await dialog.getByLabel("Customer").selectOption({ label: customer });
  await dialog.getByLabel("User ID").fill("Keys Page Key <keys-page@example.com>");
  await dialog.getByRole("button", { name: "Generate key pair" }).click();

  // The new key's page opens.
  await expect(page.getByRole("status")).toContainText("Generated key Keys Page Key");
  await expect(page.getByRole("heading", { level: 1, name: "Keys Page Key" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Breadcrumbs" })).toContainText(customer);
});

test("import a partner's public key by pasting it", async ({ page }) => {
  const customerUrl = await createCustomer(page, unique("Brightwave Retail"));
  const armored = partnerPublicKey("Brightwave SFTP <sftp@brightwave.example>");

  await page.goto(customerUrl);
  await page.getByRole("button", { name: "Import keys" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Import keys" });
  await dialog.getByLabel("…or paste an armored key").fill(armored);
  await dialog.getByRole("button", { name: "Import", exact: true }).click();
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

test("revoking asks first, then marks the key revoked", async ({ page }) => {
  const customerUrl = await createCustomer(page, unique("Nordic Freight"));
  await generateKey(page, customerUrl, "Nordic Old <old@nordic.example>");

  // With JavaScript the tick box gives way to a dialog. Cancelling leaves the key alone.
  await expect(page.getByLabel("Revoke this key permanently")).toBeHidden();
  await page.getByLabel("Reason").selectOption("retired");
  await page.getByRole("button", { name: "Revoke key" }).click();
  const dialog = page.getByRole("dialog", { name: "Revoke key?" });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.locator(".page-head .pill")).toHaveText("valid");

  await page.getByRole("button", { name: "Revoke key" }).click();
  await dialog.getByRole("button", { name: "Revoke key" }).click();
  await expect(page.getByRole("status")).toContainText("Revoked key");
  await expect(page.locator(".page-head .pill")).toHaveText("revoked");

  await page.goto("/keys?show=revoked");
  await expect(page.locator(".key-row", { hasText: "old@nordic.example" })).toBeVisible();
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("deleting a key needs the tick box", async ({ page }) => {
    // The dialogs still open: browsers do that themselves (invoker commands).
    const customerUrl = await createCustomer(page, unique("No Script"));
    await generateKey(page, customerUrl, "No Script Key <noscript@example.com>");

    // The browser refuses the form until the box is ticked.
    await page.getByRole("button", { name: "Delete key" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "No Script Key" })).toBeVisible();
    await page.getByLabel("Delete this key").check();
    await page.getByRole("button", { name: "Delete key" }).click();
    await expect(page.getByRole("status")).toContainText("Deleted key No Script Key");
  });
});
