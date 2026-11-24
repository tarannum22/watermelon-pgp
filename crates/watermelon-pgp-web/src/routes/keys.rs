use axum::{
    extract::{Multipart, Path, Query, State},
    http::header,
    response::{IntoResponse, Redirect, Response},
};
use maud::{Markup, html};
use serde::Deserialize;
use watermelon_pgp_core::{
    audit::{Actor, Filter},
    crypto::{self, Algorithm, RevocationReason},
    store::{Customer, KeyRecord},
};
use zeroize::Zeroizing;

use super::{Confirmed, Empty, Names};
use crate::{
    AppState,
    auth::{Authed, CSRF_FIELD, Posted},
    error::AppError,
    ui::{self, Tone, icons},
    views::{self, Nav},
};

/// Minimum passphrase length for exported secret keys.
const MIN_EXPORT_PASSPHRASE_LEN: usize = 8;

/// Keys as rich rows: who, status, fingerprint, what they can do, expiry.
pub fn key_list(keys: &[&KeyRecord], with_customer: bool) -> Markup {
    html! {
        @if keys.is_empty() {
            (ui::empty(icons::KEY, "No keys", "Generate a key pair or import the public key a partner sent you.", None))
        } @else {
            div.key-list {
                @for key in keys {
                    (key_row(key, with_customer))
                }
            }
        }
    }
}

fn key_row(key: &KeyRecord, with_customer: bool) -> Markup {
    let (tone, state) = views::key_state(key);
    let avatar_tone = match tone {
        Tone::Good if key.has_secret => Tone::Good,
        Tone::Good => Tone::Neutral,
        other => other,
    };
    let other_ids = key.user_ids.len().saturating_sub(1);
    let (name, email) = views::uid_parts(key.label());
    html! {
        div.key-row.revoked[key.revoked] {
            (ui::avatar(name, avatar_tone))
            div.key-main {
                div.key-title {
                    a.key-name href={ "/keys/" (key.fingerprint) } { (name) }
                    (ui::pill(tone, &state))
                    @if key.has_secret { (ui::tag("key pair", "we hold the secret key", true)) } @else { (ui::tag("public", "public key only", false)) }
                }
                @if email.is_some() || other_ids > 0 {
                    span.key-sub {
                        @if let Some(email) = email { (email) }
                        @if other_ids > 0 { " " span.subtle { "+" (other_ids) " more user IDs" } }
                    }
                }
                div.key-meta {
                    (ui::fingerprint(&key.fingerprint, true))
                    (ui::tag(&key.algorithm, "algorithm", false))
                    (views::key_capabilities(key))
                    @if with_customer {
                        span { (ui::icon_with(icons::CUSTOMERS, "icon sm")) }
                        a href={ "/customers/" (key.customer_id) } { (key.customer_name) }
                    }
                }
            }
            div.key-side {
                span { "Expires " @match key.expires_at { Some(at) => (views::date(at)), None => "never" } }
                span.subtle { "Created " (views::date(key.created_at)) }
            }
        }
    }
}

/// The "Generate a key pair" dialog, opened by `.opens("generate-key")`.
pub fn generate_modal(csrf: &str, customer: &Customer) -> Markup {
    let placeholder = format!("{} <pgp@example.com>", customer.name);
    ui::modal(
        "generate-key",
        "Generate a key pair",
        html! {
            form.form method="post" action={ "/customers/" (customer.id) "/keys/generate" } {
                (views::csrf_field(csrf))
                (ui::field("User ID", Some("Name and email address partners will see on the key."), html! {
                    input type="text" name="user_id" required maxlength="500" placeholder=(placeholder) autofocus;
                }))
                (ui::field("Algorithm", None, html! {
                    select name="algorithm" {
                        option value="curve25519" selected { "Ed25519 + Cv25519 (recommended)" }
                        option value="rsa4096" { "RSA 4096 (for older partners; slow to generate)" }
                    }
                }))
                div.actions { (ui::button("Generate key pair").primary().icon(icons::KEY)) }
            }
        },
    )
}

/// The "Import keys" dialog, opened by `.opens("import-keys")`.
pub fn import_modal(csrf: &str, customer: &Customer) -> Markup {
    ui::modal(
        "import-keys",
        "Import keys",
        html! {
            form.form method="post" action={ "/customers/" (customer.id) "/keys/import" }
                enctype="multipart/form-data" {
                (views::csrf_field(csrf))
                (ui::field("Key file", Some("Armored (.asc) or binary (.gpg, .pgp)."), html! { input type="file" name="file"; }))
                (ui::field("…or paste an armored key", None, html! {
                    textarea name="armored" rows="5" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----" {}
                }))
                (ui::optional_field("Passphrase", Some("Only for protected secret keys. Secret keys are re-encrypted under the master key; the passphrase is not kept."), html! {
                    input type="password" name="passphrase" autocomplete="off";
                }))
                div.actions { (ui::button("Import").primary().icon(icons::UPLOAD)) }
            }
        },
    )
}

/// Which keys the list shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Show {
    All,
    KeyPairs,
    Public,
    Attention,
    Revoked,
}

const SHOW: &[(Show, &str, &str)] = &[
    (Show::All, "", "All keys"),
    (Show::KeyPairs, "pairs", "Key pairs"),
    (Show::Public, "public", "Public only"),
    (Show::Attention, "attention", "Needs attention"),
    (Show::Revoked, "revoked", "Revoked"),
];

impl Show {
    fn matches(self, key: &KeyRecord) -> bool {
        match self {
            Show::All => true,
            Show::KeyPairs => key.has_secret,
            Show::Public => !key.has_secret,
            Show::Attention => views::key_needs_attention(key),
            Show::Revoked => key.revoked,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ListQuery {
    show: String,
    q: String,
}

fn key_matches_text(key: &KeyRecord, text: &str) -> bool {
    let text = text.to_lowercase();
    let hex = text.replace(' ', "").to_uppercase();
    key.user_ids
        .iter()
        .any(|uid| uid.to_lowercase().contains(&text))
        || key.customer_name.to_lowercase().contains(&text)
        || (!hex.is_empty() && key.fingerprint.contains(&hex))
}

pub async fn list(
    State(state): State<AppState>,
    auth: Authed,
    Query(query): Query<ListQuery>,
) -> Result<Markup, AppError> {
    let keys = state.vault(|vault| vault.keys(None)).await?;
    let show = SHOW
        .iter()
        .find(|(_, value, _)| *value == query.show)
        .map_or(Show::All, |(show, _, _)| *show);
    let text = query.q.trim();
    let shown: Vec<&KeyRecord> = keys
        .iter()
        .filter(|k| show.matches(k) && (text.is_empty() || key_matches_text(k, text)))
        .collect();
    let url = |value: &str| {
        let params: Vec<(&str, &str)> = [("show", value), ("q", text)]
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .collect();
        match serde_html_form::to_string(&params).unwrap_or_default() {
            query if query.is_empty() => "/keys".to_owned(),
            query => format!("/keys?{query}"),
        }
    };
    let page = state.page(&auth, "Keys", Nav::Keys);
    Ok(views::layout(
        page,
        html! {
            (ui::page_header("Keys")
                .subtitle(html! { "All keys of all customers. To add keys, open a " a href="/customers" { "customer" } "." }))
            (ui::panel(key_list(&shown, true))
                .actions(html! {
                    form.inline-search method="get" action="/keys" role="search" {
                        @if show != Show::All { input type="hidden" name="show" value=(query.show); }
                        (ui::search_input("q", text, "Name, email, customer or fingerprint", "Search keys"))
                        (ui::button("Search").small())
                    }
                })
                .description(html! {
                    span.chips {
                        @for (option, value, label) in SHOW {
                            (ui::chip(&url(value), label, Some(keys.iter().filter(|k| option.matches(k)).count()), *option == show))
                        }
                    }
                })
                .flush()
                .footer(html! {
                    span { "Showing " (shown.len()) " of " (keys.len()) " keys" }
                    @if !text.is_empty() || show != Show::All { a href="/keys" { "Clear filters" } }
                }))
        },
    ))
}

pub async fn show(
    State(state): State<AppState>,
    auth: Authed,
    Path(fpr): Path<String>,
) -> Result<Markup, AppError> {
    let (key, used_by, events, customers, jobs) = state
        .vault(move |vault| {
            let key = vault.find_key(&fpr)?;
            let events = vault.query_audit(&Filter {
                key_fingerprint: Some(key.fingerprint.clone()),
                limit: 15,
                ..Filter::default()
            })?;
            let used_by = vault.jobs_using_key(&key.fingerprint)?;
            Ok((key, used_by, events, vault.customers()?, vault.jobs()?))
        })
        .await?;
    let names = Names::new(&customers, &jobs);
    let page = state.page(&auth, key.label(), Nav::Keys);
    let (name, _) = views::uid_parts(key.label());
    let base = format!("/keys/{}", key.fingerprint);
    let customer_url = format!("/customers/{}", key.customer_id);
    let (tone, state_text) = views::key_state(&key);
    let min_passphrase = MIN_EXPORT_PASSPHRASE_LEN.to_string();
    Ok(views::layout(
        page,
        html! {
            (ui::page_header(name)
                .crumb("Customers", "/customers")
                .crumb(&key.customer_name, customer_url.clone())
                .status(ui::pill(tone, &state_text))
                .subtitle(html! {
                    @if key.has_secret { "Key pair: we hold the secret key." } @else { "Public key of a partner." }
                }))

            (ui::panel(html! {
                div.key-details {
                    (ui::fingerprint_box(&key.fingerprint))
                    dl.kv {
                        dt { "User IDs" } dd { @for uid in &key.user_ids { div { (uid) } } }
                        dt { "Customer" } dd { a href=(customer_url) { (key.customer_name) } }
                        dt { "Algorithm" } dd { (key.algorithm) }
                        dt { "Can" } dd { (views::key_capabilities(&key)) }
                    }
                    dl.kv {
                        dt { "Created" } dd { (views::timestamp(key.created_at)) }
                        dt { "Expires" } dd { @match key.expires_at { Some(at) => (views::timestamp(at)), None => "never" } }
                        dt { "Added" } dd { (views::timestamp(key.added_at)) }
                        dt { "Used by jobs" } dd {
                            @if used_by.is_empty() { span.muted { "none" } } @else { (used_by.join(", ")) }
                        }
                    }
                }
            }).title("Key").icon(icons::FINGERPRINT))

            div.grid-2 {
                (ui::panel(html! {
                    // A download, not a page: keep htmx out of it.
                    form.form.fill method="post" action={ (base) "/public" } hx-boost="false" {
                        (views::csrf_field(&auth.csrf))
                        p { "Share this with partners so they can encrypt to us or check our signatures." }
                        div.actions { (ui::button("Download public key (.asc)").icon(icons::DOWNLOAD)) }
                    }
                }).title("Public key").icon(icons::DOWNLOAD))
                @if key.has_secret {
                    (ui::panel(html! {
                        form.form.fill method="post" action={ (base) "/secret" } hx-boost="false" {
                            (views::csrf_field(&auth.csrf))
                            p { "The export is protected with a new passphrase. Exports are audited." }
                            div.form-row {
                                (ui::field("New passphrase", None, html! { input type="password" name="passphrase" required minlength=(min_passphrase) autocomplete="new-password"; }))
                                (ui::field("Repeat passphrase", None, html! { input type="password" name="repeat" required minlength=(min_passphrase) autocomplete="new-password"; }))
                            }
                            div.actions { (ui::button("Download secret key (.asc)").icon(icons::LOCK)) }
                        }
                    }).title("Export secret key").icon(icons::LOCK))
                }
            }

            (ui::panel(views::audit_table(&events, &names))
                .title("Recent activity")
                .icon(icons::ACTIVITY)
                .actions(views::activity_search(Some(("key", key.fingerprint.clone()))))
                .flush())

            @if key.has_secret && !key.revoked {
                (ui::panel(html! {
                    form.form method="post" action={ (base) "/revoke" } {
                        (views::csrf_field(&auth.csrf))
                        p {
                            "Revoking tells everyone who has the public key to stop using it. It cannot be undone. "
                            "Jobs encrypting to or signing with this key pause; it can still decrypt older files. "
                            "Afterwards, send partners the public key again so they learn about the revocation."
                        }
                        div.form-row {
                            (ui::field("Reason", None, html! {
                                select name="reason" {
                                    option value="superseded" { "Replaced by a new key" }
                                    option value="retired" { "No longer used" }
                                    option value="compromised" { "Compromised (secret key leaked)" }
                                    option value="unspecified" { "No reason given" }
                                }
                            }))
                            (ui::optional_field("Comment", None, html! { input type="text" name="comment" maxlength="500"; }))
                        }
                        (ui::confirm("Revoke this key permanently"))
                        div.actions { (ui::button("Revoke key").danger().icon(icons::BAN)) }
                    }
                }).title("Revoke key").icon(icons::BAN).tone(Tone::Bad))
            }
            (ui::panel(html! {
                @if used_by.is_empty() {
                    form.form method="post" action={ (base) "/delete" } {
                        (views::csrf_field(&auth.csrf))
                        p { "Deleted keys stay in the database so the audit log keeps resolving, but can no longer be used." }
                        (ui::confirm("Delete this key"))
                        div.actions { (ui::button("Delete key").danger().icon(icons::TRASH)) }
                    }
                } @else {
                    p { "This key is used by " (used_by.join(", ")) ". Change or delete those jobs first." }
                }
            }).title("Delete key").icon(icons::TRASH).tone(Tone::Bad))
        },
    ))
}

#[derive(Deserialize)]
pub struct RevokeForm {
    #[serde(default)]
    confirm: String,
    reason: String,
    #[serde(default)]
    comment: String,
}

pub async fn revoke(
    State(state): State<AppState>,
    Path(fpr): Path<String>,
    posted: Posted<RevokeForm>,
) -> Redirect {
    let back = key_url(&fpr);
    let form = posted.form;
    let outcome = async {
        Confirmed {
            confirm: form.confirm,
        }
        .check()?;
        let reason = match form.reason.as_str() {
            "superseded" => RevocationReason::Superseded,
            "retired" => RevocationReason::Retired,
            "compromised" => RevocationReason::Compromised,
            "unspecified" => RevocationReason::Unspecified,
            other => return Err(AppError::bad_request(format!("unknown reason {other:?}"))),
        };
        let key = state
            .vault(move |vault| vault.revoke_key(Actor::Admin, &fpr, reason, &form.comment))
            .await?;
        Ok(format!(
            "Revoked key {}. Download its public key again and send it to partners.",
            key.label()
        ))
    }
    .await;
    state.done(&posted.auth, &back, outcome)
}

#[derive(Deserialize)]
pub struct GenerateForm {
    user_id: String,
    algorithm: String,
}

pub async fn generate(
    State(state): State<AppState>,
    Path(customer_id): Path<i64>,
    posted: Posted<GenerateForm>,
) -> Redirect {
    let back = format!("/customers/{customer_id}");
    let outcome = async {
        let algorithm = match posted.form.algorithm.as_str() {
            "curve25519" => Algorithm::Curve25519,
            "rsa4096" => Algorithm::Rsa4096,
            other => {
                return Err(AppError::bad_request(format!(
                    "unknown algorithm {other:?}"
                )));
            }
        };
        let user_id = posted.form.user_id.trim().to_owned();
        if user_id.is_empty() {
            return Err(AppError::bad_request("the user ID must not be empty"));
        }
        // Make sure the customer exists before spending seconds on an RSA key.
        state
            .vault(move |vault| vault.customer_by_id(customer_id))
            .await?;
        // Generate outside the vault lock, which the job engine shares.
        let key = tokio::task::spawn_blocking(move || crypto::generate(&user_id, algorithm))
            .await
            .map_err(AppError::internal)??;
        let record = state
            .vault(move |vault| vault.add_generated_key(Actor::Admin, customer_id, key))
            .await?;
        Ok(format!(
            "Generated key {} ({}).",
            record.label(),
            views::key_id(&record.fingerprint)
        ))
    }
    .await;
    state.done(&posted.auth, &back, outcome)
}

pub async fn import(
    State(state): State<AppState>,
    auth: Authed,
    Path(customer_id): Path<i64>,
    multipart: Multipart,
) -> Response {
    let back = format!("/customers/{customer_id}");
    let outcome = import_upload(&state, &auth, customer_id, multipart).await;
    if let Err(e) = &outcome
        && e.status == axum::http::StatusCode::FORBIDDEN
    {
        // Failed CSRF check: don't act on the request at all.
        return AppError::new(e.status, e.message()).into_response();
    }
    state.done(&auth, &back, outcome).into_response()
}

async fn import_upload(
    state: &AppState,
    auth: &Authed,
    customer_id: i64,
    mut multipart: Multipart,
) -> Result<String, AppError> {
    let mut csrf = String::new();
    let mut data = Vec::new();
    let mut pasted = String::new();
    let mut passphrase = Zeroizing::new(String::new());
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(format!("upload failed: {e}")))?
    {
        let name = field.name().unwrap_or("").to_owned();
        let bad = |e: axum::extract::multipart::MultipartError| {
            AppError::bad_request(format!("upload failed: {e}"))
        };
        match name.as_str() {
            CSRF_FIELD => csrf = field.text().await.map_err(bad)?,
            "file" => data = field.bytes().await.map_err(bad)?.to_vec(),
            "armored" => pasted = field.text().await.map_err(bad)?,
            "passphrase" => *passphrase = field.text().await.map_err(bad)?,
            _ => {}
        }
    }
    auth.check_csrf(&csrf)?;
    if data.is_empty() {
        data = pasted.trim().as_bytes().to_vec();
    }
    if data.is_empty() {
        return Err(AppError::bad_request("choose a key file or paste a key"));
    }
    let imported = state
        .vault(move |vault| {
            let passphrase = Some(passphrase.as_str()).filter(|p| !p.is_empty());
            vault.import_keys(Actor::Admin, customer_id, &data, passphrase)
        })
        .await?;
    let summary: Vec<String> = imported
        .iter()
        .map(|key| {
            format!(
                "{} ({}{})",
                key.label(),
                views::key_id(&key.fingerprint),
                if key.has_secret { ", secret" } else { "" }
            )
        })
        .collect();
    Ok(format!("Imported or updated {}.", summary.join(", ")))
}

pub async fn export_public(
    State(state): State<AppState>,
    Path(fpr): Path<String>,
    posted: Posted<Empty>,
) -> Response {
    let result = state
        .vault(move |vault| {
            let key = vault.find_key(&fpr)?;
            Ok((vault.export_public(Actor::Admin, &key.fingerprint)?, key))
        })
        .await;
    match result {
        Ok((armored, key)) => download(&key, "public", armored),
        Err(e) => state.done(&posted.auth, "/keys", Err(e)).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ExportSecretForm {
    passphrase: String,
    repeat: String,
}

pub async fn export_secret(
    State(state): State<AppState>,
    Path(fpr): Path<String>,
    posted: Posted<ExportSecretForm>,
) -> Response {
    let back = key_url(&fpr);
    let passphrase = Zeroizing::new(posted.form.passphrase);
    let repeat = Zeroizing::new(posted.form.repeat);
    if passphrase.chars().count() < MIN_EXPORT_PASSPHRASE_LEN {
        let e = AppError::bad_request(format!(
            "the passphrase must be at least {MIN_EXPORT_PASSPHRASE_LEN} characters"
        ));
        return state.done(&posted.auth, &back, Err(e)).into_response();
    }
    if *passphrase != *repeat {
        let e = AppError::bad_request("the two passphrases do not match");
        return state.done(&posted.auth, &back, Err(e)).into_response();
    }
    let result = state
        .vault(move |vault| {
            let key = vault.find_key(&fpr)?;
            Ok((
                vault.export_secret(Actor::Admin, &key.fingerprint, &passphrase)?,
                key,
            ))
        })
        .await;
    match result {
        Ok((armored, key)) => download(&key, "secret", armored),
        Err(e) => state.done(&posted.auth, &back, Err(e)).into_response(),
    }
}

/// The key's page, if `fpr` looks like a fingerprint. Path values are user input and end up
/// in a `Location` header.
fn key_url(fpr: &str) -> String {
    if !fpr.is_empty() && fpr.bytes().all(|b| b.is_ascii_hexdigit()) {
        format!("/keys/{fpr}")
    } else {
        "/keys".to_owned()
    }
}

fn download(key: &KeyRecord, kind: &str, armored: String) -> Response {
    let customer: String = key
        .customer_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let file_name = format!("{customer}-{}-{kind}.asc", views::key_id(&key.fingerprint));
    (
        [
            (header::CONTENT_TYPE, "application/pgp-keys".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file_name}\""),
            ),
        ],
        armored,
    )
        .into_response()
}

pub async fn delete(
    State(state): State<AppState>,
    Path(fpr): Path<String>,
    posted: Posted<Confirmed>,
) -> Redirect {
    let back = key_url(&fpr);
    if let Err(e) = posted.form.check() {
        return state.done(&posted.auth, &back, Err(e));
    }
    match state
        .vault(move |vault| vault.delete_key(Actor::Admin, &fpr))
        .await
    {
        Ok(key) => state.done(
            &posted.auth,
            &format!("/customers/{}", key.customer_id),
            Ok(format!("Deleted key {}.", key.label())),
        ),
        Err(e) => state.done(&posted.auth, &back, Err(e)),
    }
}
