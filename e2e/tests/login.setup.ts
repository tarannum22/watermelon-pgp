import { expect, test as setup } from "@playwright/test";
import { PASSWORD } from "../support/env";

// Log in once; the other tests reuse the session (see storageState in the config).
setup("log in as admin", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("Admin password").fill(PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  await page.context().storageState({ path: ".run/admin.json" });
});
