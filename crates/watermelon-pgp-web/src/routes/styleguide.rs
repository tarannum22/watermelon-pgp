//! The living style guide: every design-system component in every state, rendered by the
//! same code as the real pages. Only in debug builds.

use axum::extract::State;
use maud::{Markup, Render, html};

use crate::{
    AppState,
    auth::Authed,
    ui::{self, Icon, Stat, Theme, Tone},
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
    let page = state.page(&auth, "Style guide", Nav::Styleguide);
    let tones = [
        (Tone::Neutral, "disabled"),
        (Tone::Good, "running"),
        (Tone::Warn, "expires in 12 days"),
        (Tone::Bad, "paused"),
    ];
    views::layout(
        page,
        html! {
            (ui::page_header("Style guide")
                .crumb("Development build", "/styleguide")
                .subtitle(html! {
                    "Every component, rendered by " code { "src/ui/mod.rs" } " with the tokens in "
                    code { "assets/css/tokens.css" } ". See " code { "docs/design-system.md" } "."
                }))

            (ui::alert(Tone::Warn, Some("Development build"), html! {
                "This page exists only in debug builds. Release builds don't include it."
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
            }).title("Colour tokens").icon(Icon::Palette)
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
                }).title("Type").icon(Icon::Edit))
                (ui::panel(html! {
                    div.specimen {
                        @for icon in Icon::ALL {
                            span title=(format!("{icon:?}")) { (ui::icon_with(*icon, "icon lg")) }
                        }
                    }
                }).title("Icons").icon(Icon::Palette)
                  .description(html! { "Lucide, inlined from " code { "src/ui/icons.rs" } ". Hover for the " code { "Icon" } " variant." }))
            }

            (ui::panel(html! {
                div.btn-row {
                    (ui::button("Default"))
                    (ui::button("Primary").primary().icon(Icon::Plus))
                    (ui::button("Danger").danger().icon(Icon::Trash))
                    (ui::button("Ghost").ghost())
                    (ui::button("Small").small().icon(Icon::Retry))
                    (ui::button("Slow action").primary().icon(Icon::Key).busy("Working…"))
                    (ui::button("Link").href("/styleguide"))
                    (ui::button("Download").icon(Icon::Download).href("/styleguide").download())
                }
            }).title("Buttons").icon(Icon::Play))

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
                        (ui::chip("/styleguide", "All keys", Some(14), true))
                        (ui::chip("/styleguide", "Key pairs", Some(4), false))
                        (ui::removable_chip("/styleguide", "Last 24 hours"))
                    }
                }).title("Pills, tags and chips").icon(Icon::Filter))
                (ui::panel(html! {
                    div.specimen {
                        (ui::avatar("Alpine Outdoor GmbH", Tone::Good))
                        (ui::avatar("Brightwave Retail", Tone::Neutral))
                        (ui::avatar("Legacy Relay", Tone::Bad))
                        (ui::avatar("Expiring Partner", Tone::Warn))
                    }
                    (ui::fingerprint(SAMPLE_FPR, true))
                    (ui::fingerprint_box(SAMPLE_FPR))
                }).title("Avatars and fingerprints").icon(Icon::Fingerprint))
            }

            div.stats {
                (Stat { href: "/styleguide", icon: Icon::Jobs, label: "Jobs running", value: "3".into(), detail: "of 3 jobs".into(), tone: Tone::Neutral })
                (Stat { href: "/styleguide", icon: Icon::Key, label: "Keys", value: "14".into(), detail: "2 need attention".into(), tone: Tone::Warn })
                (Stat { href: "/styleguide", icon: Icon::FileX, label: "Files failed", value: "1".into(), detail: "last 24 hours".into(), tone: Tone::Bad })
            }

            div.grid-2 {
                div.stack {
                    p.muted.small { "Alerts sit in the page. The outcome of a form is a toast in the corner, like this one:" }
                    div.toast-demo { (ui::toast(Tone::Good, html! { "Created job daily-orders. It is running." })) }
                    (ui::alert(Tone::Good, None, html! { "Created job daily-orders. It is running." }))
                    (ui::alert(Tone::Warn, Some("Key expires soon"), html! { "Exports for Alpine Outdoor stop in 12 days." }))
                    (ui::alert(Tone::Bad, None, html! { "The input folder does not exist." }))
                    (ui::alert(Tone::Neutral, None, html! { "Retrying moves the file back into the input folder." }))
                }
                (ui::panel(ui::empty(Icon::Jobs, "No jobs yet", "Create a job to encrypt files for a partner.",
                    Some(ui::button("New job").primary().icon(Icon::Plus).href("/styleguide").render())))
                    .title("Empty state").icon(Icon::Info))
            }

            div.grid-2 {
                (ui::panel(html! {
                    div.form {
                        (ui::field("Name", Some("A hint under the control."), html! { input type="text" placeholder="daily-orders"; }))
                        (ui::optional_field("Comment", None, html! { input type="text"; }))
                        (ui::form_field("Input folder", html! {
                            input type="text" value="/srv/missing" aria-invalid="true" aria-describedby=(ui::error_id("demo-input"));
                        }).error("demo-input", Some("input folder /srv/missing does not exist")))
                        (ui::field("Select", None, html! { select { option { "Ed25519 + Cv25519" } } }))
                        div.choice-cards {
                            (ui::choice_card("demo-kind", "a", true, "Encrypt", "Files for partners."))
                            (ui::choice_card("demo-kind", "b", false, "Decrypt", "Files from partners."))
                        }
                        (ui::checkbox("demo-check", true, "A checkbox", Some("With a hint.")))
                        (ui::confirm("Confirm a destructive action"))
                        (ui::search_input("demo-q", "", "Search…", "Search"))
                    }
                }).title("Forms").icon(Icon::Edit))
                div.stack {
                    (ui::panel(html! {
                        p { "For short forms that create something, opened from the page's main action." }
                        (ui::button("Open the modal").icon(Icon::Plus).opens("design-modal"))
                        (ui::modal("design-modal", "New customer", html! {
                            div.form {
                                (ui::field("Name", Some("A hint under the control."), html! { input type="text" autofocus; }))
                                div.actions { (ui::button("Create customer").primary().icon(Icon::Plus)) }
                            }
                        }))
                    }).title("Modal").icon(Icon::Plus))
                    (ui::panel(html! {
                        form.form method="get" action="/styleguide" data-confirm="This is what the dialog says before something irreversible." {
                            (ui::confirm("Without JavaScript, this box must be ticked"))
                            div.actions { (ui::button("Delete something").danger().icon(Icon::Trash)) }
                        }
                    }).title("Confirmation").icon(Icon::Warning).tone(Tone::Bad))
                    (ui::panel(html! { p { "Panels with a danger tone hold irreversible actions." } })
                        .title("Danger zone").icon(Icon::Trash).tone(Tone::Bad))
                    (ui::panel(html! { p { "Panels with a warning tone hold things that need attention." } })
                        .title("Needs attention").icon(Icon::Warning).tone(Tone::Warn))
                    (ui::panel(ui::terminal(html! { span.comment { "# commands and armored keys" } "\nwatermelonpgp --data-dir /var/lib/watermelonpgp serve" }))
                        .title("Terminal").icon(Icon::Info))
                    (ui::panel(html! {
                        div.specimen {
                            @for theme in [Theme::System, Theme::Light, Theme::Dark] {
                                span.tag { (theme.value()) }
                            }
                        }
                        (ui::theme_switch(views::csrf_field(&auth.csrf), auth.theme))
                    }).title("Theme switch").icon(Icon::Sun))
                }
            }

            div.grid-2 {
                (ui::panel(ui::notice_list(&[
                    ui::Notice { tone: Tone::Bad, icon: Icon::Pause, what: html! { a href="/styleguide" { "Job inbound-invoices" } " is paused" }, why: "input folder /srv/in does not exist".into() },
                    ui::Notice { tone: Tone::Warn, icon: Icon::Key, what: html! { "Key " a href="/styleguide" { "Alpine Exports" } " expires in 12 days" }, why: "Alpine Outdoor GmbH".into() },
                ])).title("Needs attention").icon(Icon::Warning).tone(Tone::Warn).flush())
                (ui::panel(html! {
                    p { "Long forms number their panels, like the job form." }
                }).title("A step of a form").step(2))
            }

            (ui::panel(ui::table("", &[ui::col("Job"), ui::col("State"), ui::col("Detail"), ui::num_col("Files")], html! {
                tr { td.strong { "daily-orders" } td { (ui::pill(Tone::Good, "running")) } td { (ui::long_text("encrypted orders.csv")) } td.num { "1,428" } }
                tr.warn { td.strong { "weekly-reports" } td { (ui::pill(Tone::Warn, "error")) } td.detail { (ui::long_text(&"output folder /srv/sftp/weekly/upload is not writable: permission denied (os error 13); ".repeat(4))) } td.num { "52" } }
                tr.bad { td.strong { "inbound-invoices" } td { (ui::pill(Tone::Bad, "paused")) } td { "—" } td.num { "0" } }
            })).title("Table in a flush panel").icon(Icon::Audit).flush()
              .footer(html! { span { "Footer for totals and paging" } (ui::link_arrow("/styleguide", "See more")) }))
        },
    )
}
