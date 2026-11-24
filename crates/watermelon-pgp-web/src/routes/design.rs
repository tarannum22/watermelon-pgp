//! The living style guide: every design-system component in every state, rendered by the
//! same code as the real pages. Only in builds with the `evaluation` feature.

use axum::extract::State;
use maud::{Markup, Render, html};

use crate::{
    AppState,
    auth::Authed,
    ui::{self, Stat, Theme, Tone, icons},
    views::{self, Nav},
};

const SAMPLE_FPR: &str = "3F90A118D4C2B7619A0E403E9B4E21CF81C90DF2";

/// Colour tokens shown as swatches: (CSS variable, what it is for).
const COLORS: &[(&str, &str)] = &[
    ("--color-bg", "page background"),
    ("--color-surface", "panels"),
    ("--color-surface-sunken", "table headers, inputs"),
    ("--color-surface-muted", "chips, avatars"),
    ("--color-text", "text"),
    ("--color-text-muted", "secondary text"),
    ("--color-border", "lines"),
    ("--color-primary", "actions, brand"),
    ("--color-primary-soft", "selected, good"),
    ("--color-warn", "needs attention"),
    ("--color-warn-soft", "warning background"),
    ("--color-bad", "failure, danger"),
    ("--color-bad-soft", "failure background"),
    ("--color-terminal-bg", "commands"),
];

pub async fn show(State(state): State<AppState>, auth: Authed) -> Markup {
    let page = state.page(&auth, "Design system", Nav::Design);
    let tones = [
        (Tone::Neutral, "disabled"),
        (Tone::Good, "running"),
        (Tone::Warn, "expires in 12 days"),
        (Tone::Bad, "paused"),
    ];
    views::layout(
        page,
        html! {
            (ui::page_header("Design system")
                .crumb("Evaluation build", "/design")
                .subtitle(html! {
                    "Every component, rendered by " code { "src/ui/mod.rs" } " with the tokens in "
                    code { "assets/css/tokens.css" } ". See " code { "docs/design-system.md" } "."
                }))

            (ui::alert(Tone::Warn, Some("Evaluation build"), html! {
                "This page exists only in builds with the " code { "evaluation" } " feature. Release builds don't include it."
            }))

            (ui::panel(html! {
                div.swatches {
                    @for (name, purpose) in COLORS {
                        div.swatch {
                            // The CSP forbids style attributes: each swatch has a class in pages.css.
                            span class={ "sw-" (name.trim_start_matches("--color-")) } {}
                            code { (name) br; span.subtle { (purpose) } }
                        }
                    }
                }
            }).title("Colour tokens").icon(icons::PALETTE)
              .description(html! { "Roles, not hues. Each has a light and a dark value; switch the theme in the sidebar to compare." }))

            div.grid-2 {
                (ui::panel(html! {
                    div.type-scale {
                        h1 { "Page title, 28" }
                        h2 { "Section title, 16" }
                        p { "Body text, 14. Geist for text; JetBrains Mono for " code { "code" } ", fingerprints and labels." }
                        p.small.muted { "Secondary text, 13." }
                        span.stat-label { "Label, 11, mono, uppercase" }
                    }
                }).title("Type").icon(icons::EDIT))
                (ui::panel(html! {
                    div.specimen {
                        @for svg in [icons::DASHBOARD, icons::JOBS, icons::AUDIT, icons::CUSTOMERS, icons::KEY, icons::SETTINGS,
                                     icons::LOCK, icons::UNLOCK, icons::FINGERPRINT, icons::SHIELD, icons::WARNING, icons::FILE_X,
                                     icons::RETRY, icons::DOWNLOAD, icons::UPLOAD, icons::COPY, icons::SEARCH, icons::FILTER] {
                            (ui::icon_with(svg, "icon lg"))
                        }
                    }
                }).title("Icons").icon(icons::PALETTE)
                  .description(html! { "Lucide, inlined from " code { "src/ui/icons.rs" } "." }))
            }

            (ui::panel(html! {
                div.btn-row {
                    (ui::button("Default"))
                    (ui::button("Primary").primary().icon(icons::PLUS))
                    (ui::button("Danger").danger().icon(icons::TRASH))
                    (ui::button("Ghost").ghost())
                    (ui::button("Small").small().icon(icons::RETRY))
                    (ui::button("Link").href("/design"))
                    (ui::button("Download").icon(icons::DOWNLOAD).href("/design").download())
                }
            }).title("Buttons").icon(icons::PLAY))

            div.grid-2 {
                (ui::panel(html! {
                    div.specimen {
                        @for (tone, text) in tones { (ui::pill(tone, text)) }
                    }
                    div.specimen {
                        (ui::tag("encrypt", "can encrypt", false))
                        (ui::tag("secret", "we hold the secret key", true))
                    }
                    div.chips {
                        (ui::chip("/design", "All keys", Some(14), true))
                        (ui::chip("/design", "Key pairs", Some(4), false))
                        (ui::removable_chip("/design", "Last 24 hours"))
                    }
                }).title("Pills, tags and chips").icon(icons::FILTER))
                (ui::panel(html! {
                    div.specimen {
                        (ui::avatar("Alpine Outdoor GmbH", Tone::Good))
                        (ui::avatar("Brightwave Retail", Tone::Neutral))
                        (ui::avatar("Legacy Relay", Tone::Bad))
                        (ui::avatar("Expiring Partner", Tone::Warn))
                    }
                    (ui::fingerprint(SAMPLE_FPR, true))
                    (ui::fingerprint_box(SAMPLE_FPR))
                }).title("Avatars and fingerprints").icon(icons::FINGERPRINT))
            }

            div.stats {
                (Stat { href: "/design", icon: icons::JOBS, label: "Jobs running", value: "3".into(), detail: "of 3 jobs".into(), tone: Tone::Neutral })
                (Stat { href: "/design", icon: icons::KEY, label: "Keys", value: "14".into(), detail: "2 need attention".into(), tone: Tone::Warn })
                (Stat { href: "/design", icon: icons::FILE_X, label: "Files failed", value: "1".into(), detail: "last 24 hours".into(), tone: Tone::Bad })
            }

            div.grid-2 {
                div.stack {
                    (ui::alert(Tone::Good, None, html! { "Created job daily-orders. It is running." }))
                    (ui::alert(Tone::Warn, Some("Key expires soon"), html! { "Exports for Alpine Outdoor stop in 12 days." }))
                    (ui::alert(Tone::Bad, None, html! { "The input folder does not exist." }))
                    (ui::alert(Tone::Neutral, None, html! { "Retrying moves the file back into the input folder." }))
                }
                (ui::panel(ui::empty(icons::JOBS, "No jobs yet", "Create a job to encrypt files for a partner.",
                    Some(ui::button("New job").primary().icon(icons::PLUS).href("/design").render())))
                    .title("Empty state").icon(icons::INFO))
            }

            div.grid-2 {
                (ui::panel(html! {
                    div.form {
                        (ui::field("Name", Some("A hint under the control."), html! { input type="text" placeholder="daily-orders"; }))
                        (ui::optional_field("Comment", None, html! { input type="text"; }))
                        (ui::field("Select", None, html! { select { option { "Ed25519 + Cv25519" } } }))
                        div.choice-cards {
                            (ui::choice_card("demo-kind", "a", true, "Encrypt", "Files for partners."))
                            (ui::choice_card("demo-kind", "b", false, "Decrypt", "Files from partners."))
                        }
                        (ui::checkbox("demo-check", true, "A checkbox", Some("With a hint.")))
                        (ui::confirm("Confirm a destructive action"))
                        (ui::search_input("demo-q", "", "Search…", "Search"))
                    }
                }).title("Forms").icon(icons::EDIT))
                div.stack {
                    (ui::panel(html! {
                        p { "For short forms that create something, opened from the page's main action." }
                        (ui::button("Open the modal").icon(icons::PLUS).opens("design-modal"))
                        (ui::modal("design-modal", "New customer", html! {
                            div.form {
                                (ui::field("Name", Some("A hint under the control."), html! { input type="text" autofocus; }))
                                div.actions { (ui::button("Create customer").primary().icon(icons::PLUS)) }
                            }
                        }))
                    }).title("Modal").icon(icons::PLUS))
                    (ui::panel(html! { p { "Panels with a danger tone hold irreversible actions." } })
                        .title("Danger zone").icon(icons::TRASH).tone(Tone::Bad))
                    (ui::panel(html! { p { "Panels with a warning tone hold things that need attention." } })
                        .title("Needs attention").icon(icons::WARNING).tone(Tone::Warn))
                    (ui::panel(ui::terminal(html! { span.comment { "# commands and armored keys" } "\nwatermelon --data-dir /var/lib/watermelon serve" }))
                        .title("Terminal").icon(icons::INFO))
                    (ui::panel(html! {
                        div.specimen {
                            @for theme in [Theme::System, Theme::Light, Theme::Dark] {
                                span.tag { (theme.value()) }
                            }
                        }
                        (ui::theme_switch(views::csrf_field(&auth.csrf), auth.theme))
                    }).title("Theme switch").icon(icons::SUN))
                }
            }

            (ui::panel(html! {
                div.table-wrap {
                    table.table {
                        thead { tr { th { "Job" } th { "State" } th.num { "Files" } } }
                        tbody {
                            tr { td.strong { "daily-orders" } td { (ui::pill(Tone::Good, "running")) } td.num { "1,428" } }
                            tr.warn { td.strong { "weekly-reports" } td { (ui::pill(Tone::Warn, "error")) } td.num { "52" } }
                            tr.bad { td.strong { "inbound-invoices" } td { (ui::pill(Tone::Bad, "paused")) } td.num { "0" } }
                        }
                    }
                }
            }).title("Table in a flush panel").icon(icons::AUDIT).flush()
              .footer(html! { span { "Footer for totals and paging" } (ui::link_arrow("/design", "See more")) }))
        },
    )
}
