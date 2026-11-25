//! The design system: generic, reusable components. Pages are built from these; nothing here
//! knows about keys, jobs or customers (that's `views`).
//!
//! Each component renders the classes styled in the same-named section of
//! `assets/css/components.css`, and all styling goes through the tokens in `tokens.css`.
//! Builders (`Button`, `Panel`, `PageHeader`, `Field`) implement [`Render`], so they drop
//! straight into `html!`. Debug builds show every component in every state at `/styleguide`.

mod icons;

pub use icons::Icon;
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

    fn icon(self) -> Icon {
        match self {
            Tone::Good => Icon::Check,
            Tone::Warn => Icon::Warning,
            Tone::Bad => Icon::CircleAlert,
            Tone::Neutral => Icon::Info,
        }
    }

    /// Bad news interrupts a screen reader; everything else waits its turn.
    fn role(self) -> &'static str {
        if self == Tone::Bad { "alert" } else { "status" }
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

/// A Lucide icon, decorative (hidden from screen readers).
pub fn icon(icon: Icon) -> Markup {
    icon_with(icon, "icon")
}

pub fn icon_with(icon: Icon, class: &str) -> Markup {
    html! {
        svg class=(class) viewBox="0 0 24 24" aria-hidden="true" focusable="false" { (PreEscaped(icon.svg())) }
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
    icon: Option<Icon>,
    variant: Variant,
    small: bool,
    block: bool,
    href: Option<&'a str>,
    opens: Option<&'a str>,
    download: bool,
    busy: Option<&'a str>,
}

pub fn button(label: &str) -> Button<'_> {
    Button {
        label,
        icon: None,
        variant: Variant::Default,
        small: false,
        block: false,
        href: None,
        opens: None,
        download: false,
        busy: None,
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
    pub fn icon(mut self, icon: Icon) -> Self {
        self.icon = Some(icon);
        self
    }
    /// Make it a link.
    pub fn href(mut self, href: &'a str) -> Self {
        self.href = Some(href);
        self
    }
    /// Open the [`modal`] with this id instead of submitting.
    pub fn opens(mut self, modal_id: &'a str) -> Self {
        self.opens = Some(modal_id);
        self
    }
    /// A file download: a normal request, not an htmx swap.
    pub fn download(mut self) -> Self {
        self.download = true;
        self
    }
    /// What the button says while its form is being sent, for slow actions such as generating
    /// an RSA key. Shown with a spinner.
    pub fn busy(mut self, label: &'a str) -> Self {
        self.busy = Some(label);
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
            span.btn-label { (self.label) }
            @if let Some(busy) = self.busy { span.btn-busy aria-hidden="true" { (busy) } }
        };
        let boost = self.download.then_some("false");
        match (self.href, self.opens) {
            (Some(href), _) => html! {
                a class=(self.class()) href=(href) hx-boost=[boost] download[self.download] { (inner) }
            },
            (None, Some(id)) => html! {
                button class=(self.class()) type="button" commandfor=(id) command="show-modal" { (inner) }
            },
            (None, None) => html! { button class=(self.class()) type="submit" { (inner) } },
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
                                (icon_with(Icon::ChevronRight, "icon sm"))
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
    icon: Option<Icon>,
    step: Option<u8>,
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
        step: None,
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
    pub fn icon(mut self, icon: Icon) -> Self {
        self.icon = Some(icon);
        self
    }
    /// Number the panel as a step of a longer form, in place of its icon.
    pub fn step(mut self, number: u8) -> Self {
        self.step = Some(number);
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
    /// No padding around the body: for tables and lists that run edge to edge. Put anything
    /// that needs padding in a [`panel_section`].
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
                                @if let Some(number) = self.step {
                                    span.step-number { span.visually-hidden { "Step " } (number) }
                                } @else if let Some(svg) = self.icon {
                                    (icon(svg))
                                }
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

/// A padded part of a [`Panel::flush`] panel, such as a summary above a table.
pub fn panel_section(body: Markup) -> Markup {
    html! { div.panel-section { (body) } }
}

// Stat

/// A number on the dashboard, linking to the details behind it.
pub struct Stat<'a> {
    pub href: &'a str,
    pub icon: Icon,
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

// Table

/// A table column heading. Numeric columns are right-aligned.
#[derive(Debug, Clone, Copy)]
pub struct Column<'a> {
    label: &'a str,
    numeric: bool,
}

pub fn col(label: &str) -> Column<'_> {
    Column {
        label,
        numeric: false,
    }
}

pub fn num_col(label: &str) -> Column<'_> {
    Column {
        label,
        numeric: true,
    }
}

/// A table with sticky headings; `rows` are the `tr`s. Put it in a [`Panel::flush`] panel.
/// Give numeric cells `td.num`, and a row `tr.bad` or `tr.warn` to make it stand out.
pub fn table(class: &str, columns: &[Column<'_>], rows: Markup) -> Markup {
    html! {
        div.table-wrap {
            table class={ "table " (class) } {
                thead {
                    tr {
                        @for column in columns {
                            th.num[column.numeric] { (column.label) }
                        }
                    }
                }
                tbody { (rows) }
            }
        }
    }
}

/// Text that can run long (paths, error details): the first lines, and the rest on demand.
pub fn long_text(text: &str) -> Markup {
    const SHORT: usize = 160;
    html! {
        @if text.chars().count() <= SHORT && !text.contains('\n') {
            (text)
        } @else {
            details.long-text {
                summary { span.clamp { (text) } span.more { "Show all" } span.less { "Show less" } }
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
            span.idle { (icon(Icon::Copy)) }
            span.done { (icon(Icon::Check)) }
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
            (label) (icon_with(Icon::Close, "icon sm"))
        }
    }
}

// Empty state

/// What to show instead of an empty list, and what to do about it.
pub fn empty(svg: Icon, title: &str, text: &str, action: Option<Markup>) -> Markup {
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

/// A message in a box on the page: form errors and notices. The outcome of what the user just
/// did is a [`toast`] instead.
pub fn alert(tone: Tone, title: Option<&str>, text: Markup) -> Markup {
    html! {
        div class={ "alert " (tone.class()) } role=(tone.role()) {
            (icon(tone.icon()))
            div.alert-text {
                @if let Some(title) = title { strong { (title) } }
                (text)
            }
        }
    }
}

// Toast

/// The outcome of what the user just did, in the corner of the screen. Good news fades after a
/// few seconds; bad news stays until closed.
pub fn toast(tone: Tone, text: Markup) -> Markup {
    html! {
        div.toasts {
            div class={ "toast " (tone.class()) } role=(tone.role()) {
                (icon(tone.icon()))
                div.toast-text { (text) }
                button.toast-close type="button" aria-label="Close" { (icon_with(Icon::Close, "icon sm")) }
            }
        }
    }
}

// Notice list

/// One thing that needs attention: what, and why.
pub struct Notice {
    pub tone: Tone,
    pub icon: Icon,
    pub what: Markup,
    pub why: String,
}

/// Things that need attention, most urgent first. For a flush panel.
pub fn notice_list(notices: &[Notice]) -> Markup {
    html! {
        ul.notices {
            @for notice in notices {
                li class=(notice.tone.class()) {
                    (icon(notice.icon))
                    span.notice-what {
                        (notice.what)
                        @if !notice.why.is_empty() { span.notice-why { (notice.why) } }
                    }
                }
            }
        }
    }
}

// Forms

/// A labelled form control. The label wraps the control, so clicking it focuses the control;
/// the hint sits outside the label so it isn't read out as part of the field's name.
pub fn field(label: &str, hint: Option<&str>, control: Markup) -> Markup {
    form_field(label, control).hint(hint).render()
}

/// Like [`field`], marked optional.
pub fn optional_field(label: &str, hint: Option<&str>, control: Markup) -> Markup {
    form_field(label, control).hint(hint).optional().render()
}

/// The id of the error message under the field named `name`, for the control's
/// `aria-describedby`.
pub fn error_id(name: &str) -> String {
    format!("{name}-error")
}

/// A form field with everything: hint, optional marker, and the server's complaint about it.
/// For a field with an error, give the control `aria-invalid="true"` and
/// `aria-describedby=(error_id(name))`.
#[must_use]
pub struct Field<'a> {
    label: &'a str,
    hint: Option<&'a str>,
    optional: bool,
    error: Option<(&'a str, &'a str)>,
    group: bool,
    control: Markup,
}

pub fn form_field(label: &str, control: Markup) -> Field<'_> {
    Field {
        label,
        hint: None,
        optional: false,
        error: None,
        group: false,
        control,
    }
}

impl<'a> Field<'a> {
    pub fn hint(mut self, hint: Option<&'a str>) -> Self {
        self.hint = hint;
        self
    }
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
    /// What's wrong with the field named `name`, if anything.
    pub fn error(mut self, name: &'a str, message: Option<&'a str>) -> Self {
        self.error = message.map(|message| (name, message));
        self
    }
    /// Several controls under one heading (a list of checkboxes): a `fieldset` with a legend.
    pub fn group(mut self) -> Self {
        self.group = true;
        self
    }
}

impl Render for Field<'_> {
    fn render(&self) -> Markup {
        let label = html! {
            (self.label)
            @if self.optional { " " span.optional { "(optional)" } }
        };
        let error_id = self.error.map(|(name, _)| error_id(name));
        let error = html! {
            @if let (Some((_, message)), Some(id)) = (self.error, &error_id) {
                p.field-error id=(id) { (icon_with(Icon::CircleAlert, "icon sm")) (message) }
            }
        };
        let hint = html! { @if let Some(hint) = self.hint { span.hint { (hint) } } };
        if self.group {
            html! {
                fieldset.field.invalid[self.error.is_some()] aria-describedby=[error_id.as_deref()] {
                    legend.field-label { (label) }
                    (hint)
                    (self.control)
                    (error)
                }
            }
        } else {
            html! {
                div.field.invalid[self.error.is_some()] {
                    label {
                        span.field-label { (label) }
                        (self.control)
                    }
                    (hint)
                    (error)
                }
            }
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

/// The tick box of a form that does something irreversible. Give the form
/// `data-confirm="<question>"`: with JavaScript, submitting asks in the [`confirm_dialog`]
/// instead and the box is hidden; without, the browser refuses the form until it's ticked.
pub fn confirm(label: &str) -> Markup {
    html! {
        label.check.confirm-box {
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
            (icon(Icon::Search))
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

// Modal

/// A modal `<dialog>`, opened by a [`Button::opens`] with the same id. The page behind it is
/// inert while it's open; Esc, the close button or a click outside close it. Browsers open it
/// with invoker commands; `app.js` does it for those without.
pub fn modal(id: &str, title: &str, body: Markup) -> Markup {
    html! {
        dialog.modal id=(id) aria-labelledby={ (id) "-title" } closedby="any" {
            div.modal-head {
                h2.panel-title id={ (id) "-title" } { (title) }
                button.btn.ghost.sm type="button" commandfor=(id) command="close" aria-label="Close" {
                    (icon_with(Icon::Close, "icon sm"))
                }
            }
            div.modal-body { (body) }
        }
    }
}

/// The dialog that asks before a `form[data-confirm]` is sent (see [`confirm`]). One per page;
/// `app.js` fills in the question and the button.
pub fn confirm_dialog() -> Markup {
    html! {
        dialog.modal #confirm-dialog aria-labelledby="confirm-dialog-title" aria-describedby="confirm-dialog-text" closedby="any" {
            div.modal-head {
                h2.panel-title #confirm-dialog-title { (icon(Icon::Warning)) span data-confirm-title { "Are you sure?" } }
            }
            div.modal-body {
                p #confirm-dialog-text data-confirm-text {}
                div.btn-row.end {
                    button.btn type="button" commandfor="confirm-dialog" command="close" autofocus { "Cancel" }
                    button.btn.danger type="button" data-confirm-ok { "Confirm" }
                }
            }
        }
    }
}

// Theme switch

/// System / light / dark, as three submit buttons: works without JavaScript.
pub fn theme_switch(csrf_field: Markup, current: Theme) -> Markup {
    let options = [
        (Theme::System, Icon::Monitor, "Use the system theme"),
        (Theme::Light, Icon::Sun, "Light theme"),
        (Theme::Dark, Icon::Moon, "Dark theme"),
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
    html! { a.link-arrow href=(href) { (label) (icon(Icon::ArrowRight)) } }
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
        let opener = button("New").opens("new-thing").render().into_string();
        assert!(opener.contains(r#"type="button" commandfor="new-thing" command="show-modal""#));
        let slow = button("Generate")
            .busy("Generating…")
            .render()
            .into_string();
        assert!(slow.contains(r#"<span class="btn-busy" aria-hidden="true">Generating…</span>"#));
    }

    #[test]
    fn field_errors_are_tied_to_the_field() {
        let html = form_field("Input folder", html! { input name="input"; })
            .error("input", Some("input folder /x does not exist"))
            .render()
            .into_string();
        assert!(html.starts_with(r#"<div class="field invalid">"#), "{html}");
        assert!(
            html.contains(r#"<p class="field-error" id="input-error">"#),
            "{html}"
        );
        let fine = form_field("Input folder", html! {})
            .error("input", None)
            .render()
            .into_string();
        assert!(!fine.contains("invalid") && !fine.contains("field-error"));
    }

    #[test]
    fn long_text_can_be_expanded() {
        assert_eq!(long_text("short").into_string(), "short");
        let long = "x".repeat(400);
        assert!(
            long_text(&long)
                .into_string()
                .starts_with(r#"<details class="long-text">"#)
        );
    }
}
