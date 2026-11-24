import { expect, test } from "@playwright/test";
import { PASSWORD } from "../support/env";

test.describe("logging in and out", () => {
  // Start without the shared session.
  test.use({ storageState: { cookies: [], origins: [] } });

  test("pages need a login", async ({ page }) => {
    await page.goto("/keys");
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.getByRole("heading", { name: "Log in" })).toBeVisible();
  });

  test("a wrong password is refused", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Admin password").fill("not the password");
    await page.getByRole("button", { name: "Log in" }).click();
    await expect(page.getByRole("alert")).toHaveText("Wrong password.");
    await expect(page).toHaveURL(/\/login$/);
  });

  test("log in, then log out", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Admin password").fill(PASSWORD);
    await page.getByRole("button", { name: "Log in" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();

    await page.getByRole("button", { name: "Log out" }).click();
    await expect(page).toHaveURL(/\/login$/);
    await page.goto("/");
    await expect(page).toHaveURL(/\/login$/);
  });
});
