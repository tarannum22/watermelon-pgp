// Shared by playwright.website.config.ts, demo.ts and the screenshot run.

/** The image to photograph: the release's, `ghcr.io/tarannum22/watermelon-pgp:X.Y.Z`. */
export const IMAGE = process.env.WEBSITE_IMAGE ?? "";
/** The version the screenshots must show: the image's `X.Y.Z` tag unless given; empty if neither. */
export const VERSION = process.env.WEBSITE_VERSION ?? IMAGE.match(/:(\d+\.\d+\.\d+)$/)?.[1] ?? "";
export const PORT = Number(process.env.WEBSITE_PORT ?? 18090);
export const BASE_URL = `http://127.0.0.1:${PORT}`;
export const PASSWORD = "website-demo-password";
export const CONTAINER = "watermelonpgp-website-demo";
