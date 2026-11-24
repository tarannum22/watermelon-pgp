//! Static files, embedded in the binary.
//!
//! Pages link to them with a hash of their content in the URL (`/static/app.css?v=3f9a…`), so
//! they can be cached forever and a changed file always gets a new URL, even when the version
//! number stays the same (development builds, or a browser that saw an older build).
//! Fonts are referenced from the CSS by file name, which carries their version instead.

use std::{collections::HashMap, sync::LazyLock};

use sha2::{Digest, Sha256};

/// The stylesheet, assembled at compile time from the design system's layers.
const APP_CSS: &str = concat!(
    include_str!("../assets/css/tokens.css"),
    include_str!("../assets/css/base.css"),
    include_str!("../assets/css/layout.css"),
    include_str!("../assets/css/components.css"),
    include_str!("../assets/css/pages.css"),
);

/// Name, content type, content.
const FILES: &[(&str, &str, &[u8])] = &[
    (
        "htmx.min.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../assets/htmx.min.js"),
    ),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../assets/app.js"),
    ),
    ("app.css", "text/css; charset=utf-8", APP_CSS.as_bytes()),
    (
        "logo.svg",
        "image/svg+xml",
        include_bytes!("../assets/logo.svg"),
    ),
    (
        "geist-1.9.0.woff2",
        "font/woff2",
        include_bytes!("../assets/fonts/geist-1.9.0.woff2"),
    ),
    (
        "jetbrains-mono-5.3.0.woff2",
        "font/woff2",
        include_bytes!("../assets/fonts/jetbrains-mono-5.3.0.woff2"),
    ),
];

/// The first 12 hex digits of each file's SHA-256, computed once.
static HASHES: LazyLock<HashMap<&'static str, String>> = LazyLock::new(|| {
    FILES
        .iter()
        .map(|(name, _, body)| (*name, hex::encode(Sha256::digest(body))[..12].to_owned()))
        .collect()
});

/// A file's content type and content.
pub fn get(name: &str) -> Option<(&'static str, &'static [u8])> {
    FILES
        .iter()
        .find(|(file, _, _)| *file == name)
        .map(|(_, content_type, body)| (*content_type, *body))
}

/// The URL to link to a file with.
pub fn url(name: &str) -> String {
    match HASHES.get(name) {
        Some(hash) => format!("/static/{name}?v={hash}"),
        None => format!("/static/{name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_change_with_the_content() {
        let css = url("app.css");
        assert!(
            css.starts_with("/static/app.css?v=") && css.len() == "/static/app.css?v=".len() + 12
        );
        assert_ne!(url("app.css"), url("app.js"));
        assert!(get("app.css").is_some_and(|(kind, _)| kind.starts_with("text/css")));
        assert!(get("../Cargo.toml").is_none());
    }
}
