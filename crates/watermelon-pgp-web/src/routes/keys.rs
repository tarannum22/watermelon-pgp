use axum::{
    extract::{Multipart, Path, Query, State},
    http::header,
    response::{IntoResponse, Redirect, Response},
};
use maud::{Markup, Render, html};
use serde::Deserialize;
use watermelon_pgp_core::{
    audit::{Actor, Filter},
    crypto::{self, Algorithm, RevocationReason},
    store::{Customer, KeyOwner, KeyRecord},
};
use zeroize::Zeroizing;

use super::{Confirmed, Empty, Names};
use crate::{
    AppState,
    auth::{Authed, CSRF_FIELD, Posted},
    error::AppError,
    ui::{self, Icon, Tone},
    views::{self, Nav},
};

/// Minimum passphrase length for exported secret keys.
const MIN_EXPORT_PASSPHRASE_LEN: usize = 8;

/// The customer picker of the Keys page's dialogs: a customer, or explicitly none.
fn owner_select(customers: &[Customer]) -> Markup {
    ui::field(
        "Customer",
        Some("Who the key is for. A key without a customer is an anonymous key."),
        html! {
            select name="customer" required autofocus {
                option value="" { "Choose…" }
                option value=(ANONYMOUS) { "No customer (anonymous key)" }
                @for customer in customers {
                    option value=(customer.id) { (customer.name) }
                }
            }
        },
    )
}

/// The `customer` form value for "no customer".
const ANONYMOUS: &str = "none";

/// The customer picked in [`owner_select`]: `None` for an anonymous key.
fn picked_owner(value: &str) -> Result<Option<i64>, AppError> {
    match value.trim() {
        ANONYMOUS => Ok(None),
        other => super::parse_id(other)
            .map(Some)
            .ok_or_else(|| AppError::bad_request("choose a customer, or no customer")),
    }
}

/// Whose key a dialog creates: a given customer's, or one picked in the dialog.
pub enum Owner<'a> {
    Customer(&'a Customer),
    Choose(&'a [Customer]),
}

impl Owner<'_> {
    /// Where the dialog's form posts `what` (`generate`, `import`): under the customer, or to
    /// the Keys page's own route.
    fn action(&self, what: &str) -> String {
        match self {
            Owner::Customer(customer) => format!("/customers/{}/keys/{what}", customer.id),
            Owner::Choose(_) => format!("/keys/{what}"),
        }
    }

    /// The customer picker, when the dialog asks for one.
    fn picker(&self) -> Option<Markup> {
        match self {
            Owner::Customer(_) => None,
            Owner::Choose(customers) => Some(owner_select(customers)),
        }
    }
}

/// The "Generate a key pair" dialog, opened by `.opens("generate-key")`.
pub fn generate_modal(csrf: &str, owner: Owner<'_>) -> Markup {
    let placeholder = match &owner {
        Owner::Customer(customer) => format!("{} <pgp@example.com>", customer.name),
        Owner::Choose(_) => "Name <pgp@example.com>".to_owned(),
    };
    ui::modal(
        "generate-key",
        "Generate a key pair",
        html! {
            form.form method="post" action=(owner.action("generate")) {
                (views::csrf_field(csrf))
                @if let Some(picker) = owner.picker() { (picker) }
                (ui::field("User ID", Some("Name and email address partners will see on the key."), html! {
                    input type="text" name="user_id" required maxlength="500" placeholder=(placeholder)
                        autofocus[owner.picker().is_none()];
                }))
                (ui::field("Algorithm", None, html! {
                    select name="algorithm" {
                        option value="curve25519" selected { "Ed25519 + Cv25519 (recommended)" }
                        option value="rsa4096" { "RSA 4096 (for older partners; slow to generate)" }
                    }
                }))
                div.actions { (ui::button("Generate key pair").primary().icon(Icon::Key).busy("Generating…")) }
            }
        },
    )
}

/// The "Import keys" dialog, opened by `.opens("import-keys")`.
pub fn import_modal(csrf: &str, owner: Owner<'_>) -> Markup {
    ui::modal(
        "import-keys",
        "Import keys",
        html! {
            form.form method="post" action=(owner.action("import")) enctype="multipart/form-data" {
                (views::csrf_field(csrf))
                @if let Some(picker) = owner.picker() { (picker) }
                (ui::field("Key file", Some("Armored (.asc) or binary (.gpg, .pgp)."), html! { input type="file" name="file"; }))
                (ui::field("…or paste an armored key", None, html! {
                    textarea name="armored" rows="5" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----" {}
                }))
                (ui::optional_field("Passphrase", Some("Only for protected secret keys. Secret keys are re-encrypted under the master key; the passphrase is not kept."), html! {
                    input type="password" name="passphrase" autocomplete="off";
                }))
                div.actions { (ui::button("Import").primary().icon(Icon::Upload).busy("Importing…")) }
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
    Anonymous,
}

const SHOW: &[(Show, &str, &str)] = &[
    (Show::All, "", "All keys"),
    (Show::KeyPairs, "pairs", "Key pairs"),
    (Show::Public, "public", "Public only"),
    (Show::Attention, "attention", "Needs attention"),
    (Show::Revoked, "revoked", "Revoked"),
    (Show::Anonymous, "anonymous", "Anonymous"),
];

impl Show {
    fn matches(self, key: &KeyRecord) -> bool {
        match self {
            Show::All => true,
            Show::KeyPairs => key.has_secret,
            Show::Public => !key.has_secret,
            Show::Attention => views::key_needs_attention(key),
            Show::Revoked => key.revoked,
            Show::Anonymous => key.owner == KeyOwner::Anonymous,
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
        || views::owner_name(key).to_lowercase().contains(&text)
        || (!hex.is_empty() && key.fingerprint.contains(&hex))
}

pub async fn list(
    State(state): State<AppState>,
    auth: Authed,
    Query(query): Query<ListQuery>,
) -> Result<Markup, AppError> {
    let (keys, customers) = state
        .vault(|vault| Ok((vault.keys(None)?, vault.customers()?)))
        .await?;
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
                .subtitle(html! { "All keys: those of your customers, and anonymous keys that belong to no customer." })
                .actions(html! {
                    (ui::button("Import keys").icon(Icon::Upload).opens("import-keys"))
                    (ui::button("Generate key pair").primary().icon(Icon::Key).opens("generate-key"))
                }))
            (generate_modal(&auth.csrf, Owner::Choose(&customers)))
            (import_modal(&auth.csrf, Owner::Choose(&customers)))
            (ui::panel(html! {
                @if keys.is_empty() {
                    (ui::empty(Icon::Key, "No keys yet", "Generate a key pair of your own, or import the public key a partner sent you.",
                        Some(html! {
                            div.btn-row {
                                (ui::button("Generate key pair").primary().icon(Icon::Key).opens("generate-key"))
                                (ui::button("Import keys").icon(Icon::Upload).opens("import-keys"))
                            }
                        })))
                } @else if shown.is_empty() {
                    (ui::empty(Icon::Search, "No keys match", "Try another filter or search.",
                        Some(ui::button("Clear filters").href("/keys").render())))
                } @else {
                    (views::key_list(&shown, true))
                }
            })
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
    let (tone, state_text) = views::key_state(&key);
    let min_passphrase = MIN_EXPORT_PASSPHRASE_LEN.to_string();
    Ok(views::layout(
        page,
        html! {
            (match &key.owner {
                KeyOwner::Customer { id, name: customer } => ui::page_header(name)
                    .crumb("Customers", "/customers")
                    .crumb(customer, format!("/customers/{id}")),
                KeyOwner::Anonymous => ui::page_header(name).crumb("Keys", "/keys"),
            }
                .status(ui::pill(tone, &state_text))
                .subtitle(html! {
                    @if key.has_secret { "Key pair: we hold the secret key." } @else { "Public key of a partner." }
                }))

            (ui::panel(html! {
                div.key-details {
                    (ui::fingerprint_box(&key.fingerprint))
                    dl.kv {
                        dt { "User IDs" } dd { @for uid in &key.user_ids { div { (uid) } } }
                        dt { "Customer" } dd { (views::key_owner(&key)) }
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
            }).title("Key").icon(Icon::Fingerprint))

            div.grid-2 {
                (ui::panel(html! {
                    // A download, not a page: keep htmx out of it.
                    form.form.fill method="post" action={ (base) "/public" } hx-boost="false" {
                        (views::csrf_field(&auth.csrf))
                        p { "Share this with partners so they can encrypt to us or check our signatures." }
                        div.actions { (ui::button("Download public key (.asc)").icon(Icon::Download)) }
                    }
                }).title("Public key").icon(Icon::Download))
                @if key.has_secret {
                    (ui::panel(html! {
                        form.form.fill method="post" action={ (base) "/secret" } hx-boost="false" {
                            (views::csrf_field(&auth.csrf))
                            p { "The export is protected with a new passphrase. Exports are audited." }
                            div.form-row {
                                (ui::field("New passphrase", None, html! { input type="password" name="passphrase" required minlength=(min_passphrase) autocomplete="new-password"; }))
                                (ui::field("Repeat passphrase", None, html! { input type="password" name="repeat" required minlength=(min_passphrase) autocomplete="new-password"; }))
                            }
                            div.actions { (ui::button("Download secret key (.asc)").icon(Icon::Lock)) }
                        }
                    }).title("Export secret key").icon(Icon::Lock))
                }
            }

            (ui::panel(views::audit_table(&events, &names))
                .title("Recent activity")
                .icon(Icon::Activity)
                .actions(views::activity_search(Some(("key", key.fingerprint.clone()))))
                .flush())

            @if key.has_secret && !key.revoked {
                (ui::panel(html! {
                    form.form method="post" action={ (base) "/revoke" } data-confirm="Partners who have the public key will stop using it. This cannot be undone." {
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
                        div.actions { (ui::button("Revoke key").danger().icon(Icon::Ban)) }
                    }
                }).title("Revoke key").icon(Icon::Ban).tone(Tone::Bad))
            }
            (ui::panel(html! {
                @if used_by.is_empty() {
                    form.form method="post" action={ (base) "/delete" } data-confirm="The key can no longer be used. Its audit history stays." {
                        (views::csrf_field(&auth.csrf))
                        p { "Deleted keys stay in the database so the audit log keeps resolving, but can no longer be used." }
                        (ui::confirm("Delete this key"))
                        div.actions { (ui::button("Delete key").danger().icon(Icon::Trash)) }
                    }
                } @else {
                    p { "This key is used by " (used_by.join(", ")) ". Change or delete those jobs first." }
                }
            }).title("Delete key").icon(Icon::Trash).tone(Tone::Bad))
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
    /// Only from the Keys page; on a customer's page the URL says whose key it is.
    #[serde(default)]
    customer: String,
    user_id: String,
    algorithm: String,
}

/// Generate a key pair from a customer's page; back there afterwards.
pub async fn generate_for_customer(
    State(state): State<AppState>,
    Path(customer_id): Path<i64>,
    posted: Posted<GenerateForm>,
) -> Redirect {
    let back = format!("/customers/{customer_id}");
    let outcome = generate_key(&state, Some(customer_id), &posted.form)
        .await
        .map(|record| generated(&record));
    state.done(&posted.auth, &back, outcome)
}

/// Generate a key pair from the Keys page, for the customer picked in the form or as an
/// anonymous key; on to the new key's page.
pub async fn generate(State(state): State<AppState>, posted: Posted<GenerateForm>) -> Redirect {
    let outcome = async {
        let customer_id = picked_owner(&posted.form.customer)?;
        generate_key(&state, customer_id, &posted.form).await
    }
    .await;
    match outcome {
        Ok(record) => state.done(
            &posted.auth,
            &key_url(&record.fingerprint),
            Ok(generated(&record)),
        ),
        Err(e) => state.done(&posted.auth, "/keys", Err(e)),
    }
}

fn generated(record: &KeyRecord) -> String {
    format!(
        "Generated key {} ({}).",
        record.label(),
        views::key_id(&record.fingerprint)
    )
}

async fn generate_key(
    state: &AppState,
    customer_id: Option<i64>,
    form: &GenerateForm,
) -> Result<KeyRecord, AppError> {
    let algorithm = match form.algorithm.as_str() {
        "curve25519" => Algorithm::Curve25519,
        "rsa4096" => Algorithm::Rsa4096,
        other => {
            return Err(AppError::bad_request(format!(
                "unknown algorithm {other:?}"
            )));
        }
    };
    let user_id = form.user_id.trim().to_owned();
    if user_id.is_empty() {
        return Err(AppError::bad_request("the user ID must not be empty"));
    }
    // Make sure the customer exists before spending seconds on an RSA key.
    if let Some(id) = customer_id {
        state.vault(move |vault| vault.customer_by_id(id)).await?;
    }
    // Generate outside the vault lock, which the job engine shares.
    let key = tokio::task::spawn_blocking(move || crypto::generate(&user_id, algorithm))
        .await
        .map_err(AppError::internal)??;
    state
        .vault(move |vault| vault.add_generated_key(Actor::Admin, customer_id, key))
        .await
}

/// Import keys from a customer's page; back there afterwards.
pub async fn import_for_customer(
    State(state): State<AppState>,
    auth: Authed,
    Path(customer_id): Path<i64>,
    multipart: Multipart,
) -> Response {
    let back = format!("/customers/{customer_id}");
    let outcome = import_upload(&state, &auth, Some(customer_id), multipart)
        .await
        .map(|(message, _)| message);
    if let Err(e) = &outcome
        && e.status == axum::http::StatusCode::FORBIDDEN
    {
        // Failed CSRF check: don't act on the request at all.
        return AppError::new(e.status, e.message()).into_response();
    }
    state.done(&auth, &back, outcome).into_response()
}

/// Import keys from the Keys page, for the customer picked in the form or as anonymous keys;
/// on to the key's page when it was one key.
pub async fn import(State(state): State<AppState>, auth: Authed, multipart: Multipart) -> Response {
    let outcome = import_upload(&state, &auth, None, multipart).await;
    match outcome {
        Err(e) if e.status == axum::http::StatusCode::FORBIDDEN => {
            AppError::new(e.status, e.message()).into_response()
        }
        Ok((message, fingerprints)) => {
            let to = match fingerprints.as_slice() {
                [one] => key_url(one),
                _ => "/keys".to_owned(),
            };
            state.done(&auth, &to, Ok(message)).into_response()
        }
        Err(e) => state.done(&auth, "/keys", Err(e)).into_response(),
    }
}

/// Read an import form and import its keys: for `customer_id`, or (when `None`) for the
/// customer picked in the form. Returns the message to show and the imported fingerprints.
async fn import_upload(
    state: &AppState,
    auth: &Authed,
    customer_id: Option<i64>,
    mut multipart: Multipart,
) -> Result<(String, Vec<String>), AppError> {
    let from_url = customer_id.is_some();
    let mut picked = String::new();
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
            "customer" => picked = field.text().await.map_err(bad)?,
            _ => {}
        }
    }
    auth.check_csrf(&csrf)?;
    let customer_id = if from_url {
        customer_id
    } else {
        picked_owner(&picked)?
    };
    if data.is_empty() {
        data = pasted.trim().as_bytes().to_vec();
    }
    if data.is_empty() {
        return Err(AppError::bad_request("choose a key file or paste a key"));
    }
    let imported = state
        .vault(move |vault| {
            // An unknown customer is a 404, not a foreign key error from the database.
            if let Some(id) = customer_id {
                vault.customer_by_id(id)?;
            }
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
    Ok((
        format!("Imported or updated {}.", summary.join(", ")),
        imported.into_iter().map(|key| key.fingerprint).collect(),
    ))
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
    let customer: String = views::owner_name(key)
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
            &key.owner
                .customer_id()
                .map_or("/keys".to_owned(), |id| format!("/customers/{id}")),
            Ok(format!("Deleted key {}.", key.label())),
        ),
        Err(e) => state.done(&posted.auth, &back, Err(e)),
    }
}
