import { expect, test } from "@playwright/test";

test("the theme switch is remembered, also on the login page", async ({ page, context }) => {
  await page.goto("/settings");
  const html = page.locator("html");
  await expect(html).not.toHaveAttribute("data-theme");

  await page.locator(".sidebar").getByRole("button", { name: "Dark theme" }).click();
  await expect(html).toHaveAttribute("data-theme", "dark");
  await expect(page).toHaveURL(/\/settings$/); // back where the switch was used
  await page.reload();
  await expect(html).toHaveAttribute("data-theme", "dark");

  // Same browser, logged out: the login page uses it too.
  const anonymous = await context.browser()!.newContext({
    storageState: { cookies: (await context.cookies()).filter((c) => c.name === "watermelon_theme"), origins: [] },
  });
  const login = await anonymous.newPage();
  await login.goto("/login");
  await expect(login.locator("html")).toHaveAttribute("data-theme", "dark");
  await anonymous.close();

  await page.locator(".sidebar").getByRole("button", { name: "Use the system theme" }).click();
  await expect(html).not.toHaveAttribute("data-theme");
});
