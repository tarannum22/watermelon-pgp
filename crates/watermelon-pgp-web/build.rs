//! Builds the static files the binary serves: bundles the design system's stylesheets into one
//! minified `app.css` (lightningcss), and hashes every file for its URL. The result is a table
//! that `src/assets.rs` includes, so nothing is computed at startup.

use std::{env, fmt::Write as _, fs, path::PathBuf};

use lightningcss::stylesheet::{MinifyOptions, ParserOptions, PrinterOptions, StyleSheet};
use sha2::{Digest, Sha256};

/// The stylesheet's layers, in cascade order (see docs/design-system.md).
const CSS_LAYERS: &[&str] = &["tokens", "base", "layout", "components", "views", "pages"];

/// Served files: name, content type, source. `None` is the bundled stylesheet.
const FILES: &[(&str, &str, Option<&str>)] = &[
    (
        "htmx.min.js",
        "text/javascript; charset=utf-8",
        Some("assets/htmx.min.js"),
    ),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        Some("assets/app.js"),
    ),
    ("app.css", "text/css; charset=utf-8", None),
    ("logo.svg", "image/svg+xml", Some("assets/logo.svg")),
    (
        "geist-1.9.0.woff2",
        "font/woff2",
        Some("assets/fonts/geist-1.9.0.woff2"),
    ),
    (
        "jetbrains-mono-5.3.0.woff2",
        "font/woff2",
        Some("assets/fonts/jetbrains-mono-5.3.0.woff2"),
    ),
];

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    // Every served file is copied here, so the table below doesn't depend on where the
    // sources are.
    let static_dir = out_dir.join("static");
    fs::create_dir_all(&static_dir).expect("creating the static directory");

    let mut table = String::from("/// Name, content type, content, hash of the content.\n");
    table.push_str("const FILES: &[(&str, &str, &[u8], &str)] = &[\n");
    for (name, content_type, source) in FILES {
        let body = match source {
            Some(source) => {
                println!("cargo::rerun-if-changed={source}");
                fs::read(crate_dir.join(source)).unwrap_or_else(|e| panic!("{source}: {e}"))
            }
            None => bundle_css(&crate_dir).into_bytes(),
        };
        fs::write(static_dir.join(name), &body).unwrap_or_else(|e| panic!("{name}: {e}"));
        let hash = &hex::encode(Sha256::digest(&body))[..12];
        writeln!(
            table,
            "    ({name:?}, {content_type:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/static/{name}\")), {hash:?}),"
        )
        .expect("writing to a string");
    }
    table.push_str("];\n");
    fs::write(out_dir.join("assets.rs"), table).expect("writing assets.rs");
}

/// The layers concatenated and minified. Fails the build on CSS that doesn't parse.
fn bundle_css(crate_dir: &std::path::Path) -> String {
    let mut source = String::new();
    for layer in CSS_LAYERS {
        let path = format!("assets/css/{layer}.css");
        println!("cargo::rerun-if-changed={path}");
        let layer =
            fs::read_to_string(crate_dir.join(&path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        source.push_str(&layer);
        source.push('\n');
    }
    let mut sheet = StyleSheet::parse(&source, ParserOptions::default())
        .unwrap_or_else(|e| panic!("app.css: {e}"));
    sheet
        .minify(MinifyOptions::default())
        .unwrap_or_else(|e| panic!("minifying app.css: {e}"));
    sheet
        .to_css(PrinterOptions {
            minify: true,
            ..PrinterOptions::default()
        })
        .unwrap_or_else(|e| panic!("printing app.css: {e}"))
        .code
}
