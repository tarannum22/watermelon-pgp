import { expect, test } from "@playwright/test";

// The style guide is only in debug builds, which is what these tests run against.
test("the style guide shows the components", async ({ page }) => {
  await page.goto("/styleguide");
  await expect(page.getByRole("heading", { level: 1, name: "Style guide" })).toBeVisible();
  for (const section of ["Colour tokens", "Buttons", "Pills, tags and chips", "Forms", "Confirmation", "Table in a flush panel"]) {
    await expect(page.getByRole("heading", { name: section })).toBeVisible();
  }
  await expect(page.locator(".dev-badge")).toBeVisible();
});

test("no page breaks the Content-Security-Policy", async ({ page }) => {
  const violations: string[] = [];
  page.on("console", (message) => {
    if (/Content Security Policy|Refused to/i.test(message.text())) violations.push(message.text());
  });
  for (const path of ["/", "/customers", "/keys", "/jobs", "/jobs/new", "/audit", "/settings", "/styleguide"]) {
    await page.goto(path);
  }
  expect(violations).toEqual([]);
});

test("the new-customer modal opens from the header and closes with Escape", async ({ page }) => {
  await page.goto("/customers");
  const dialog = page.getByRole("dialog", { name: "New customer" });
  await expect(dialog).toBeHidden();
  await page.getByRole("button", { name: "New customer" }).first().click();
  await expect(dialog).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await page.getByRole("button", { name: "New customer" }).first().click();
  await dialog.getByRole("button", { name: "Close" }).click();
  await expect(dialog).toBeHidden();
});

test("the modal is modal: the page behind it can't be used", async ({ page }) => {
  await page.goto("/customers");
  await page.getByRole("button", { name: "New customer" }).first().click();
  const dialog = page.getByRole("dialog", { name: "New customer" });
  await expect(dialog.getByLabel("Name")).toBeFocused();
  // Tab stays inside the dialog.
  for (let i = 0; i < 5; i += 1) await page.keyboard.press("Tab");
  expect(await page.evaluate(() => !!document.activeElement?.closest("dialog"))).toBe(true);
});
