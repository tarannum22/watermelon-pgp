# Design system

The web UI is built from a small design system, so it looks consistent and can be reworked in
one place. There is no framework and no JavaScript toolchain: tokens and components are plain
CSS, the components are Rust functions that render HTML (maud), and everything is compiled into
the binary.

```
assets/css/tokens.css      the only place colours, type, spacing and shapes are defined
assets/css/base.css        defaults for plain HTML elements
assets/css/layout.css      the shell: sidebar, top bar, content column, login page
assets/css/components.css  one section per component, in the same order as src/ui/mod.rs
assets/css/views.css       styles of the domain renderers in src/views.rs (the key list)
assets/css/pages.css       page-specific layout; anything reusable belongs in components
assets/app.js              enhancements: dialogs, confirmations, copy buttons, toasts
src/ui/mod.rs              the components
src/ui/icons.rs            Lucide icons, inlined, as the `Icon` enum
src/views.rs               domain renderers built on the components (key list, audit table)
src/routes/*.rs            the pages
build.rs                   bundles and minifies the CSS, hashes every static file
```

`build.rs` concatenates the six CSS files in that order, minifies them with
[lightningcss](https://lightningcss.dev) (CSS that doesn't parse fails the build) and serves the
result as `/static/app.css`. It also hashes every static file, so pages link to
`/static/app.css?v=<hash>` and browsers can cache them forever.

## Layers

1. **Tokens** (`tokens.css`) are CSS variables named by role, not by hue: `--color-bad`, not
   `--red`. Each colour holds its light and dark value with `light-dark()`, so a theme is not
   a second set of rules. Components only use tokens, never raw values.
2. **Components** (`src/ui`) know nothing about keys, jobs or customers. They take strings and
   markup and render the classes styled in `components.css`.
3. **Views** (`src/views.rs`, styled in `views.css`) turn domain objects into components: a
   key's state into a pill, keys into the key list, audit events into a table, paused jobs and
   expiring keys into notices.
4. **Pages** (`src/routes`) arrange views and components.

To change the look, start at the lowest layer that covers the change: a colour or radius in the
tokens changes it everywhere; a component's CSS changes every use of it.

## Tokens

| Group | Tokens |
|---|---|
| Surfaces | `--color-bg`, `--color-surface`, `--color-surface-sunken`, `--color-surface-muted`, `--color-surface-strong`, `--color-overlay` |
| Text | `--color-text`, `--color-text-muted`, `--color-text-subtle` |
| Lines | `--color-border`, `--color-border-strong` |
| Brand and actions | `--color-primary`, `--color-primary-hover`, `--color-on-primary`, `--color-primary-soft`, `--color-primary-soft-text`, `--color-focus` |
| Status | `--color-good*`, `--color-warn*`, `--color-bad*`, `--color-info*` (each with `-soft` background and `-text`) |
| Overlays | `--color-backdrop` (behind dialogs) |
| Code | `--color-code-bg`, `--color-terminal-bg`, `--color-terminal-text`, `--color-terminal-comment` (the terminal looks the same in both themes) |
| Type | `--font-sans` (Geist), `--font-mono` (JetBrains Mono), `--text-xs` … `--text-2xl`, `--text-stat`, `--text-mono` and `--text-mono-lg` for monospace within text |
| Spacing | `--space-1` (4px) … `--space-10` (40px), on a 4px grid |
| Shape | `--radius-sm/md/lg/pill`, `--shadow-sm/md/lg` |
| Layout | `--sidebar-width`, `--topbar-height`, `--topbar-search-max`, `--content-max` |

Brand colours come from the logo: watermelon green for actions and "good", watermelon red for
failures and danger, amber for things that need attention.

## Components

| Component | Rust | Use for |
|---|---|---|
| Icon | `ui::icon(Icon::Key)` | Decorative icons; always next to text |
| Button | `ui::button("Save").primary().icon(Icon::Check)` | Submit buttons; `.href()` for links that look like buttons, `.download()` for files, `.opens(id)` for a modal, `.busy("Generating…")` for slow actions (spinner while the form is sent) |
| Pill | `ui::pill(Tone::Good, "running")` | A status. The text says it; the colour repeats it |
| Tag | `ui::tag("encrypt", "can encrypt", false)` | Small facts such as capabilities |
| Page header | `ui::page_header("Keys").crumb(..).subtitle(..).actions(..)` | Top of every page |
| Panel | `ui::panel(body).title("Keys").icon(..).flush().footer(..)` | Every section. `.tone(Tone::Bad)` for danger zones, `.tone(Tone::Warn)` for attention, `.live(url, secs)` to refresh itself, `.step(n)` to number the panels of a long form. `ui::panel_section(..)` pads part of a flush panel |
| Table | `ui::table(class, &[ui::col("Job"), ui::num_col("Files")], rows)` | Lists in a flush panel. Headings stay in view on wide screens; rows can be `tr.bad` or `tr.warn` |
| Long text | `ui::long_text(text)` | Text that can run long (audit details): three lines, the rest behind "Show all" |
| Stat | `Stat { .. }` | Numbers on the dashboard, linking to the details |
| Fingerprint | `ui::fingerprint(fpr, short)`, `ui::fingerprint_box(fpr)` | Fingerprints, grouped in fours, with a copy button |
| Copy button | `ui::copy_button(text, what)` | Hidden unless the browser can copy |
| Chips | `ui::chip(..)`, `ui::removable_chip(..)` | Filters to pick, and active filters to remove |
| Empty state | `ui::empty(icon, title, text, action)` | Instead of an empty list: what to do next |
| Alert | `ui::alert(tone, title, text)` | Notices and form errors in the page |
| Toast | `ui::toast(tone, text)` | The outcome of a form (the layout shows flash messages this way). Good news fades; bad news stays until closed |
| Notice list | `ui::notice_list(&[Notice { .. }])` | Things that need attention, in a flush panel |
| Form fields | `ui::field`, `ui::optional_field`, `ui::form_field(..).hint(..).optional().error(name, msg).group()`, `ui::checkbox`, `ui::choice_card`, `ui::search_input` | Labelled controls; hints sit outside the label so screen readers don't read them as the name. `.error` shows the server's complaint under the field; give the control `aria-invalid` and `aria-describedby=(ui::error_id(name))`. `.group()` makes a `fieldset` for a list of checkboxes |
| Confirmation | `form data-confirm="…"` with `ui::confirm(label)` inside | Irreversible actions. With JavaScript, submitting asks in `ui::confirm_dialog()` (one per page, in the layout); without, the tick box must be ticked |
| Modal | `ui::modal(id, title, body)` with `ui::button(..).opens(id)` | Short forms that create something. A modal `<dialog>`: the page behind is inert, focus stays inside, Esc or a click outside closes it. Opened with invoker commands (`commandfor`), so it works without JavaScript; `app.js` stands in for browsers without them |
| Avatar | `ui::avatar(name, tone)` | Initials for keys and customers |
| Theme switch | `ui::theme_switch(csrf, theme)` | System / light / dark |
| Terminal | `ui::terminal(text)` | Commands and armored text |

Tables use `table.table` inside a flush panel; key-value details use `dl.kv`. Panels in a
`div.grid-2` row get the same height; give the forms of a pair of panels `form.form.fill` to
line their buttons up at the bottom.

## Rules

- **No inline styles or scripts.** The Content-Security-Policy forbids them. Use a class, and
  put behaviour in `assets/app.js`.
- **Pages work without JavaScript.** htmx and `app.js` only enhance them (live panels, copy
  buttons, filtering as you type).
- **Status is never colour alone.** Pills and alerts always carry words.
- **Both themes.** Check changes in light and dark (the switch is in the sidebar).
- **Icons are Lucide.** Add one by copying the inner elements of its SVG from
  [lucide.dev](https://lucide.dev) into `src/ui/icons.rs`, as a variant of `Icon` (and in
  `Icon::ALL`, for the style guide).

## The style guide

Debug builds serve `/styleguide`, which renders every component in every state with the same
code as the real pages, and mark themselves "Development build" in the sidebar:

```sh
cargo run -- --data-dir ./data serve
```

Release builds (`--release`: the Docker image, Homebrew, the release binaries) don't include it;
a test checks this.

## Screenshots for review

```sh
cd e2e && npm test && npm run screenshots   # every page, light and dark, in e2e/screenshots/
```

## Third-party assets

- [Geist](https://vercel.com/font) (SIL Open Font License 1.1), `assets/fonts/Geist-OFL.txt`
- [JetBrains Mono](https://www.jetbrains.com/lp/mono/) (SIL Open Font License 1.1),
  `assets/fonts/JetBrainsMono-OFL.txt`
- [Lucide](https://lucide.dev) icons (ISC), `assets/LUCIDE-LICENSE.txt`
- [htmx](https://htmx.org) (Zero-Clause BSD)
