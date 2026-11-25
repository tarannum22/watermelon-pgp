//! Static files, embedded in the binary by `build.rs`.
//!
//! Pages link to them with a hash of their content in the URL (`/static/app.css?v=3f9a…`), so
//! they can be cached forever and a changed file always gets a new URL, even when the version
//! number stays the same (development builds, or a browser that saw an older build).
//! Fonts are referenced from the CSS by file name, which carries their version instead.

include!(concat!(env!("OUT_DIR"), "/assets.rs"));

/// A file's content type and content.
pub fn get(name: &str) -> Option<(&'static str, &'static [u8])> {
    FILES
        .iter()
        .find(|(file, ..)| *file == name)
        .map(|(_, content_type, body, _)| (*content_type, *body))
}

/// The URL to link to a file with.
pub fn url(name: &str) -> String {
    match FILES.iter().find(|(file, ..)| *file == name) {
        Some((.., hash)) => format!("/static/{name}?v={hash}"),
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
