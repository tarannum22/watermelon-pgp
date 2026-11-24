import fs from "node:fs";
import { expect, test } from "@playwright/test";
import { createCustomer, htmxReady, unique } from "../support/app";

test("search, narrow down, clear filters and export the audit log", async ({ page }) => {
  const customer = unique("Audited");
  await createCustomer(page, customer);

  // The search in the top bar opens the audit log.
  await page.goto("/");
  await page.getByRole("searchbox", { name: "Search activity" }).first().fill(customer);
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/audit\?q=/);
  await expect(page.locator("#audit-results")).toContainText("1 event");
  await expect(page.locator("table.audit")).toContainText("customer.create");

  // Filters apply as you change them, and the URL follows.
  await htmxReady(page, "form.toolbar");
  await page.getByLabel("Who").selectOption("system");
  await expect(page).toHaveURL(/actor=system/);
  await expect(page.locator("#audit-results")).toContainText("0 events");

  // Each active filter is a chip that removes it.
  await page.getByRole("link", { name: "System (jobs)" }).click();
  await expect(page.locator("#audit-results")).toContainText("1 event");

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("link", { name: "Export CSV" }).click(),
  ]);
  const csv = fs.readFileSync((await download.path())!, "utf8");
  expect(csv.split("\n")[0]).toContain("action");
  expect(csv).toContain(customer);

  await page.getByRole("link", { name: "Clear all" }).click();
  await expect(page).toHaveURL(/\/audit$/);
});
