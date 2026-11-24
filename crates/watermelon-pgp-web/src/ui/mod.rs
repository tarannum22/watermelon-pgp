//! The design system: generic, reusable components. Pages are built from these; nothing here
//! knows about keys, jobs or customers (that's `views`).
//!
//! Each component renders the classes styled in the same-named section of
//! `assets/css/components.css`, and all styling goes through the tokens in `tokens.css`.
//! Builders (`Button`, `Panel`, `PageHeader`) implement [`Render`], so they drop straight into
//! `html!`. With the `evaluation` feature, `/design` shows every component in every state.

pub mod icons;

use maud::{Markup, PreEscaped, Render, html};

/// The colour of a status. Always paired with text: colour only repeats what the words say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tone {
    #[default]
    Neutral,
    Good,
    Warn,
    Bad,
}

impl Tone {
    pub fn class(self) -> &'static str {
        match self {
            Tone::Neutral => "",
            Tone::Good => "good",
            Tone::Warn => "warn",
            Tone::Bad => "bad",
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Tone::Good => icons::CHECK,
            Tone::Warn => icons::WARNING,
            Tone::Bad => icons::CIRCLE_ALERT,
            Tone::Neutral => icons::INFO,
        }
    }
}

/// The colour scheme the user picked; `System` follows the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

impl Theme {
    pub fn from_value(value: &str) -> Self {
        match value {
            "light" => Theme::Light,
            "dark" => Theme::Dark,
            _ => Theme::System,
        }
    }

    pub fn value(self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    /// The `data-theme` attribute on `<html>`; none means "follow the OS".
    pub fn attribute(self) -> Option<&'static str> {
        match self {
            Theme::System => None,
            Theme::Light => Some("light"),
            Theme::Dark => Some("dark"),
        }
    }
}

// Icon

/// A Lucide icon from [`icons`], decorative (hidden from screen readers).
pub fn icon(svg: &str) -> Markup {
    icon_with(svg, "icon")
}

pub fn icon_with(svg: &str, class: &str) -> Markup {
    html! {
        svg class=(class) viewBox="0 0 24 24" aria-hidden="true" focusable="false" { (PreEscaped(svg)) }
    }
}

// Button

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    Default,
    Primary,
    Danger,
    Ghost,
}

/// A button, or a link that looks like one. Without `href` it's a submit button for the
/// surrounding form.
#[must_use]
pub struct Button<'a> {
    label: &'a str,
    icon: Option<&'static str>,
    variant: Variant,
    small: bool,
    block: bool,
    href: Option<&'a str>,
    download: bool,
}

pub fn button(label: &str) -> Button<'_> {
    Button {
        label,
        icon: None,
        variant: Variant::Default,
        small: false,
        block: false,
        href: None,
        download: false,
    }
}

impl<'a> Button<'a> {
    pub fn primary(mut self) -> Self {
        self.variant = Variant::Primary;
        self
    }
    pub fn danger(mut self) -> Self {
        self.variant = Variant::Danger;
        self
    }
    pub fn ghost(mut self) -> Self {
        self.variant = Variant::Ghost;
        self
    }
    pub fn small(mut self) -> Self {
        self.small = true;
        self
    }
    pub fn block(mut self) -> Self {
        self.block = true;
        self
    }
    pub fn icon(mut self, svg: &'static str) -> Self {
        self.icon = Some(svg);
        self
    }
    /// Make it a link.
    pub fn href(mut self, href: &'a str) -> Self {
        self.href = Some(href);
        self
    }
    /// A file download: a normal request, not an htmx swap.
    pub fn download(mut self) -> Self {
        self.download = true;
        self
    }

    fn class(&self) -> String {
        let mut class = String::from("btn");
        match self.variant {
            Variant::Default => {}
            Variant::Primary => class.push_str(" primary"),
            Variant::Danger => class.push_str(" danger"),
            Variant::Ghost => class.push_str(" ghost"),
        }
        if self.small {
            class.push_str(" sm");
        }
        if self.block {
            class.push_str(" block");
        }
        class
    }
}

impl Render for Button<'_> {
    fn render(&self) -> Markup {
        let inner = html! {
            @if let Some(svg) = self.icon { (icon_with(svg, if self.small { "icon sm" } else { "icon" })) }
            span { (self.label) }
        };
        let boost = self.download.then_some("false");
        match self.href {
            Some(href) => html! {
                a class=(self.class()) href=(href) hx-boost=[boost] download[self.download] { (inner) }
            },
            None => html! { button class=(self.class()) type="submit" { (inner) } },
        }
    }
}

// Pill and tag

/// A status label, like "running" or "expired".
pub fn pill(tone: Tone, text: &str) -> Markup {
    html! { span class={ "pill " (tone.class()) } { (text) } }
}

/// A pill with an explanation on hover.
pub fn pill_titled(tone: Tone, text: &str, title: &str) -> Markup {
    html! { span class={ "pill " (tone.class()) } title=(title) { (text) } }
}

/// A small fact, like a capability. `strong` highlights it.
pub fn tag(text: &str, title: &str, strong: bool) -> Markup {
    html! { span.tag.strong[strong] title=(title) { (text) } }
}

// Page header

/// Breadcrumbs, title, optional status and subtitle, and the page's main actions.
#[must_use]
pub struct PageHeader<'a> {
    title: &'a str,
    crumbs: Vec<(&'a str, String)>,
    subtitle: Option<Markup>,
    status: Option<Markup>,
    actions: Option<Markup>,
}

pub fn page_header(title: &str) -> PageHeader<'_> {
    PageHeader {
        title,
        crumbs: Vec::new(),
        subtitle: None,
        status: None,
        actions: None,
    }
}

impl<'a> PageHeader<'a> {
    pub fn crumb(mut self, label: &'a str, href: impl Into<String>) -> Self {
        self.crumbs.push((label, href.into()));
        self
    }
    pub fn subtitle(mut self, subtitle: Markup) -> Self {
        self.subtitle = Some(subtitle);
        self
    }
    pub fn status(mut self, status: Markup) -> Self {
        self.status = Some(status);
        self
    }
    pub fn actions(mut self, actions: Markup) -> Self {
        self.actions = Some(actions);
        self
    }
}

impl Render for PageHeader<'_> {
    fn render(&self) -> Markup {
        html! {
            header.page-head {
                div.page-head-text {
                    @if !self.crumbs.is_empty() {
                        nav.crumbs aria-label="Breadcrumbs" {
                            @for (label, href) in &self.crumbs {
                                a href=(href) { (label) }
                                (icon_with(icons::CHEVRON_RIGHT, "icon sm"))
                            }
                        }
                    }
                    h1 { (self.title) @if let Some(status) = &self.status { (status) } }
                    @if let Some(subtitle) = &self.subtitle { p.subtitle { (subtitle) } }
                }
                @if let Some(actions) = &self.actions { div.btn-row { (actions) } }
            }
        }
    }
}

// Panel

/// The card that sections of a page sit in: optional header with title and actions, a body,
/// and an optional footer.
#[must_use]
pub struct Panel<'a> {
    title: Option<&'a str>,
    icon: Option<&'static str>,
    description: Option<Markup>,
    actions: Option<Markup>,
    body: Markup,
    footer: Option<Markup>,
    flush: bool,
    tone: Tone,
    id: Option<&'a str>,
    attrs: Option<LiveAttrs<'a>>,
}

/// htmx attributes for a panel that refreshes itself.
struct LiveAttrs<'a> {
    url: &'a str,
    every_secs: u32,
}

pub fn panel(body: Markup) -> Panel<'static> {
    Panel {
        title: None,
        icon: None,
        description: None,
        actions: None,
        body,
        footer: None,
        flush: false,
        tone: Tone::Neutral,
        id: None,
        attrs: None,
    }
}

impl<'a> Panel<'a> {
    pub fn title(self, title: &'a str) -> Panel<'a> {
        Panel {
            title: Some(title),
            ..self
        }
    }
    pub fn icon(mut self, svg: &'static str) -> Self {
        self.icon = Some(svg);
        self
    }
    pub fn description(mut self, description: Markup) -> Self {
        self.description = Some(description);
        self
    }
    pub fn actions(mut self, actions: Markup) -> Self {
        self.actions = Some(actions);
        self
    }
    pub fn footer(mut self, footer: Markup) -> Self {
        self.footer = Some(footer);
        self
    }
    /// No padding around the body: for tables and lists that run edge to edge.
    pub fn flush(mut self) -> Self {
        self.flush = true;
        self
    }
    /// `Bad` for danger zones, `Warn` for things that need attention.
    pub fn tone(mut self, tone: Tone) -> Self {
        self.tone = tone;
        self
    }
    pub fn id(self, id: &'a str) -> Panel<'a> {
        Panel {
            id: Some(id),
            ..self
        }
    }
    /// Replace itself with a fresh copy from `url` every few seconds.
    pub fn live(self, url: &'a str, every_secs: u32) -> Panel<'a> {
        Panel {
            attrs: Some(LiveAttrs { url, every_secs }),
            ..self
        }
    }
}

impl Render for Panel<'_> {
    fn render(&self) -> Markup {
        let tone = match self.tone {
            Tone::Bad => " danger",
            Tone::Warn => " warn",
            _ => "",
        };
        let (url, trigger) = match &self.attrs {
            Some(live) => (Some(live.url), Some(format!("every {}s", live.every_secs))),
            None => (None, None),
        };
        let swap = url.map(|_| "outerHTML");
        html! {
            section class={ "panel" (tone) } id=[self.id] hx-get=[url] hx-trigger=[trigger] hx-swap=[swap] {
                @if self.title.is_some() || self.actions.is_some() {
                    div.panel-head {
                        @if let Some(title) = self.title {
                            h2.panel-title {
                                @if let Some(svg) = self.icon { (icon(svg)) }
                                (title)
                            }
                        }
                        @if let Some(actions) = &self.actions { div.btn-row { (actions) } }
                        @if let Some(description) = &self.description { p.description { (description) } }
                    }
                }
                div.panel-body.flush[self.flush] { (self.body) }
                @if let Some(footer) = &self.footer { div.panel-foot { (footer) } }
            }
        }
    }
}

// Stat

/// A number on the dashboard, linking to the details behind it.
pub struct Stat<'a> {
    pub href: &'a str,
    pub icon: &'static str,
    pub label: &'a str,
    pub value: String,
    pub detail: String,
    pub tone: Tone,
}

impl Render for Stat<'_> {
    fn render(&self) -> Markup {
        html! {
            a class={ "stat " (self.tone.class()) } href=(self.href) {
                div.stat-top {
                    span.stat-label { (self.label) }
                    span.stat-icon { (icon(self.icon)) }
                }
                span.stat-value { (self.value) }
                span.stat-detail { (self.detail) }
            }
        }
    }
}

// Fingerprint

/// Hex in groups of four, as gpg prints it.
pub fn group_hex(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A fingerprint chip with a copy button. `short` shows only the long key ID.
pub fn fingerprint(fpr: &str, short: bool) -> Markup {
    let shown = if short {
        &fpr[fpr.len().saturating_sub(16)..]
    } else {
        fpr
    };
    html! {
        span.fpr.full[!short] title=(group_hex(fpr)) {
            code { (group_hex(shown)) }
            (copy_button(fpr, "fingerprint"))
        }
    }
}

/// The full fingerprint, large, for a key's own page.
pub fn fingerprint_box(fpr: &str) -> Markup {
    let grouped = group_hex(fpr);
    let half = grouped.len() / 2;
    // 10 groups: break after the fifth, like gpg does.
    let (first, second) = match grouped.match_indices(' ').nth(4) {
        Some((at, _)) if grouped.len() > 40 => (&grouped[..at], &grouped[at + 1..]),
        _ => (&grouped[..half], &grouped[half..]),
    };
    html! {
        div.fpr-box {
            code { (first) br; (second) }
            (copy_button(fpr, "fingerprint"))
        }
    }
}

// Copy button

/// Copies `text` to the clipboard. Hidden where JavaScript or the clipboard is unavailable, so
/// it never shows as a dead button.
pub fn copy_button(text: &str, what: &str) -> Markup {
    html! {
        button.copy type="button" data-copy=(text) aria-label={ "Copy " (what) } title={ "Copy " (what) } {
            span.idle { (icon(icons::COPY)) }
            span.done { (icon(icons::CHECK)) }
        }
    }
}

// Chips

/// A filter you can pick; `current` marks the active one.
pub fn chip(href: &str, label: &str, count: Option<usize>, current: bool) -> Markup {
    html! {
        a.chip href=(href) aria-current=[current.then_some("true")] {
            (label)
            @if let Some(count) = count { span.count { (count) } }
        }
    }
}

/// An active filter; following the link removes it.
pub fn removable_chip(href: &str, label: &str) -> Markup {
    html! {
        a.chip.removable href=(href) title="Remove this filter" {
            (label) (icon_with(icons::CLOSE, "icon sm"))
        }
    }
}

// Empty state

/// What to show instead of an empty list, and what to do about it.
pub fn empty(svg: &'static str, title: &str, text: &str, action: Option<Markup>) -> Markup {
    html! {
        div.empty {
            span.empty-icon { (icon(svg)) }
            strong { (title) }
            p { (text) }
            @if let Some(action) = action { (action) }
        }
    }
}

// Alert

/// A message in a box: flash messages after a form, and notices on a page.
pub fn alert(tone: Tone, title: Option<&str>, text: Markup) -> Markup {
    let role = if tone == Tone::Bad { "alert" } else { "status" };
    html! {
        div class={ "alert " (tone.class()) } role=(role) {
            (icon(tone.icon()))
            div.alert-text {
                @if let Some(title) = title { strong { (title) } }
                (text)
            }
        }
    }
}

// Forms

/// A labelled form control. The label wraps the control, so clicking it focuses the control;
/// the hint sits outside the label so it isn't read out as part of the field's name.
pub fn field(label: &str, hint: Option<&str>, control: Markup) -> Markup {
    field_with(html! { (label) }, hint, control)
}

/// Like [`field`], marked optional.
pub fn optional_field(label: &str, hint: Option<&str>, control: Markup) -> Markup {
    field_with(
        html! { (label) " " span.optional { "(optional)" } },
        hint,
        control,
    )
}

fn field_with(label: Markup, hint: Option<&str>, control: Markup) -> Markup {
    html! {
        div.field {
            label {
                span.field-label { (label) }
                (control)
            }
            @if let Some(hint) = hint { span.hint { (hint) } }
        }
    }
}

/// A checkbox with its label, and an optional hint under it.
pub fn checkbox(name: &str, checked: bool, label: &str, hint: Option<&str>) -> Markup {
    html! {
        div.check-field {
            label.check {
                input type="checkbox" name=(name) checked[checked];
                span { (label) }
            }
            @if let Some(hint) = hint { span.hint { (hint) } }
        }
    }
}

/// A required checkbox guarding destructive actions; works without JavaScript.
pub fn confirm(label: &str) -> Markup {
    html! {
        label.check {
            input type="checkbox" name="confirm" value="yes" required;
            span { (label) }
        }
    }
}

/// One of a few radio choices, shown as a card.
pub fn choice_card(name: &str, value: &str, checked: bool, title: &str, text: &str) -> Markup {
    html! {
        label.choice-card {
            input type="radio" name=(name) value=(value) checked[checked];
            span { strong { (title) } (text) }
        }
    }
}

/// A search box with an icon.
pub fn search_input(name: &str, value: &str, placeholder: &str, label: &str) -> Markup {
    html! {
        span.search {
            (icon(icons::SEARCH))
            input type="search" name=(name) value=(value) placeholder=(placeholder) aria-label=(label) autocomplete="off";
        }
    }
}

// Avatar

/// Up to two initials from a name: "Alpine Outdoor GmbH" → "AO".
pub fn initials(name: &str) -> String {
    let words: Vec<&str> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let letters: String = match words.as_slice() {
        [] => "?".into(),
        [one] => one.chars().take(2).collect(),
        [first, second, ..] => first
            .chars()
            .take(1)
            .chain(second.chars().take(1))
            .collect(),
    };
    letters.to_uppercase()
}

pub fn avatar(name: &str, tone: Tone) -> Markup {
    html! { span class={ "avatar " (tone.class()) } aria-hidden="true" { (initials(name)) } }
}

// Theme switch

/// System / light / dark, as three submit buttons: works without JavaScript.
pub fn theme_switch(csrf_field: Markup, current: Theme) -> Markup {
    let options = [
        (Theme::System, icons::MONITOR, "Use the system theme"),
        (Theme::Light, icons::SUN, "Light theme"),
        (Theme::Dark, icons::MOON, "Dark theme"),
    ];
    html! {
        // A full page load: htmx would swap only the body, and the theme lives on <html>.
        form.theme-switch method="post" action="/theme" hx-boost="false" aria-label="Theme" {
            (csrf_field)
            @for (theme, svg, label) in options {
                button type="submit" name="theme" value=(theme.value())
                    aria-pressed=(if theme == current { "true" } else { "false" })
                    title=(label) aria-label=(label) { (icon(svg)) }
            }
        }
    }
}

// Terminal

/// Commands or armored text on a dark panel.
pub fn terminal(text: Markup) -> Markup {
    html! { pre.terminal { (text) } }
}

// Links

/// "See more →" links at the end of a section.
pub fn link_arrow(href: &str, label: &str) -> Markup {
    html! { a.link-arrow href=(href) { (label) (icon(icons::ARROW_RIGHT)) } }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initials_from_names() {
        assert_eq!(initials("Alpine Outdoor GmbH"), "AO");
        assert_eq!(initials("acme"), "AC");
        assert_eq!(initials("Müller & Söhne"), "MS");
        assert_eq!(initials(""), "?");
    }

    #[test]
    fn fingerprints_are_grouped_and_copyable() {
        let fpr = "0123456789ABCDEF0123456789ABCDEF01234567";
        let html = fingerprint(fpr, true).into_string();
        assert!(html.contains("89AB CDEF 0123 4567"));
        assert!(html.contains(&format!(r#"data-copy="{fpr}""#)));
        let boxed = fingerprint_box(fpr).into_string();
        assert!(boxed.contains("0123 4567 89AB CDEF 0123<br>4567 89AB CDEF 0123 4567"));
    }

    #[test]
    fn buttons_render_as_links_or_submits() {
        let link = button("Edit").href("/jobs/1/edit").render().into_string();
        assert!(link.starts_with(r#"<a class="btn" href="/jobs/1/edit">"#));
        let download = button("CSV")
            .href("/audit.csv")
            .download()
            .render()
            .into_string();
        assert!(download.contains(r#"hx-boost="false" download"#));
        let submit = button("Delete").danger().small().render().into_string();
        assert!(submit.starts_with(r#"<button class="btn danger sm" type="submit">"#));
    }
}
