use std::path::PathBuf;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use maud::{Markup, html};
use serde::Deserialize;
use watermelon_pgp_core::{
    audit::{Actor, Filter},
    crypto::Container,
    jobs::{self, Job, JobKind, JobSpec, VerifyPolicy},
    store::{Customer, KeyRecord},
};
use watermelon_pgp_jobs::failed::{self, FailedFile};

use super::{Confirmed, Empty, Names, parse_id};
use crate::{
    AppState,
    auth::{Authed, Posted, Watching},
    error::AppError,
    views::{self, Nav, Page},
};

/// The job form's fields, as submitted. Kept as strings so a rejected form can be shown again
/// exactly as the user filled it in.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct JobForm {
    customer: String,
    name: String,
    kind: String,
    input: String,
    output: String,
    processed: String,
    delete_processed: Option<String>,
    failed: String,
    interval: String,
    recipients: Vec<String>,
    signer: String,
    armor: Option<String>,
    extension: String,
    seipd_v2: Option<String>,
    decrypt_keys: Vec<String>,
    verifiers: Vec<String>,
    verify: String,
}

impl JobForm {
    fn blank(customer: Option<i64>) -> Self {
        Self {
            customer: customer.map(|id| id.to_string()).unwrap_or_default(),
            kind: "encrypt".into(),
            interval: "30".into(),
            verify: "ignore".into(),
            ..Self::default()
        }
    }

    fn from_job(job: &Job) -> Self {
        let spec = &job.spec;
        let default_processed = spec.input_dir.join("processed");
        let default_failed = spec.input_dir.join("failed");
        Self {
            customer: job.customer_id.to_string(),
            name: spec.name.clone(),
            kind: kind_str(spec.kind).into(),
            input: spec.input_dir.display().to_string(),
            output: spec.output_dir.display().to_string(),
            processed: match &spec.processed_dir {
                Some(dir) if *dir != default_processed => dir.display().to_string(),
                _ => String::new(),
            },
            delete_processed: spec.processed_dir.is_none().then(|| "on".into()),
            failed: if spec.failed_dir == default_failed {
                String::new()
            } else {
                spec.failed_dir.display().to_string()
            },
            interval: spec.poll_interval_secs.to_string(),
            recipients: spec.recipients.clone(),
            signer: spec.signer.clone().unwrap_or_default(),
            armor: spec.armor.then(|| "on".into()),
            extension: spec.extension.clone().unwrap_or_default(),
            seipd_v2: (spec.container == Container::SeipdV2).then(|| "on".into()),
            decrypt_keys: spec.decrypt_keys.clone(),
            verifiers: spec.verifiers.clone(),
            verify: policy_str(spec.verify_policy).into(),
        }
    }

    fn customer_id(&self) -> Result<i64, AppError> {
        parse_id(&self.customer).ok_or_else(|| AppError::bad_request("choose a customer"))
    }

    /// Turn the form into a spec. The vault does the real validation (folders, keys).
    fn to_spec(&self) -> Result<JobSpec, AppError> {
        let kind = match self.kind.as_str() {
            "encrypt" => JobKind::Encrypt,
            "decrypt" => JobKind::Decrypt,
            _ => return Err(AppError::bad_request("choose encrypt or decrypt")),
        };
        let folder = |value: &str, label: &str| {
            let value = value.trim();
            if value.is_empty() {
                Err(AppError::bad_request(format!(
                    "the {label} folder is required"
                )))
            } else {
                Ok(PathBuf::from(value))
            }
        };
        let input = folder(&self.input, "input")?;
        let mut spec = JobSpec::new(&self.name, kind, &input, &folder(&self.output, "output")?);
        if self.delete_processed.is_some() {
            spec.processed_dir = None;
        } else if !self.processed.trim().is_empty() {
            spec.processed_dir = Some(PathBuf::from(self.processed.trim()));
        }
        if !self.failed.trim().is_empty() {
            spec.failed_dir = PathBuf::from(self.failed.trim());
        }
        if !self.interval.trim().is_empty() {
            spec.poll_interval_secs = self.interval.trim().parse().map_err(|_| {
                AppError::bad_request("the polling interval must be a whole number of seconds")
            })?;
        }
        match kind {
            JobKind::Encrypt => {
                spec.recipients = self.recipients.clone();
                spec.signer = Some(self.signer.clone()).filter(|s| !s.is_empty());
                spec.armor = self.armor.is_some();
                spec.extension = Some(self.extension.trim().to_owned()).filter(|e| !e.is_empty());
                if self.seipd_v2.is_some() {
                    spec.container = Container::SeipdV2;
                }
            }
            JobKind::Decrypt => {
                spec.decrypt_keys = self.decrypt_keys.clone();
                spec.verifiers = self.verifiers.clone();
                spec.verify_policy = match self.verify.as_str() {
                    "warn" => VerifyPolicy::Warn,
                    "require" => VerifyPolicy::Require,
                    _ => VerifyPolicy::Ignore,
                };
            }
        }
        Ok(spec)
    }
}

fn kind_str(kind: JobKind) -> &'static str {
    match kind {
        JobKind::Encrypt => "encrypt",
        JobKind::Decrypt => "decrypt",
    }
}

fn policy_str(policy: VerifyPolicy) -> &'static str {
    match policy {
        VerifyPolicy::Ignore => "ignore",
        VerifyPolicy::Warn => "warn",
        VerifyPolicy::Require => "require",
    }
}

/// Where the form posts to, and what it edits.
enum FormTarget<'a> {
    Create,
    Update(&'a Job),
}

struct FormData {
    customers: Vec<Customer>,
    keys: Vec<KeyRecord>,
}

async fn form_data(state: &AppState) -> Result<FormData, AppError> {
    state
        .vault(|vault| {
            Ok(FormData {
                customers: vault.customers()?,
                keys: vault.keys(None)?,
            })
        })
        .await
}

fn form_page(
    page: Page<'_>,
    form: &JobForm,
    data: &FormData,
    target: FormTarget<'_>,
    error: Option<&str>,
) -> Markup {
    let csrf = page.csrf.to_owned();
    let (heading, action) = match &target {
        FormTarget::Create => ("New job".to_owned(), "/jobs".to_owned()),
        FormTarget::Update(job) => (
            format!("Edit job {}", job.spec.name),
            format!("/jobs/{}", job.id),
        ),
    };
    let usable = |key: &KeyRecord| jobs::usable(key).is_ok();
    views::layout(
        page,
        html! {
            p.crumbs { a href="/jobs" { "Jobs" } " /" }
            h1 { (heading) }
            @if let Some(error) = error {
                p.flash.error role="alert" { (error) }
            }
            form.job method="post" action=(action) {
                (views::csrf_field(&csrf))
                fieldset {
                    legend { "Job" }
                    @match &target {
                        FormTarget::Create => {
                            label {
                                "Customer"
                                select name="customer" required {
                                    option value="" { "Choose…" }
                                    @for customer in &data.customers {
                                        option value=(customer.id) selected[form.customer == customer.id.to_string()] { (customer.name) }
                                    }
                                }
                            }
                        }
                        FormTarget::Update(job) => {
                            p { "Customer: " strong { (job.customer_name) } }
                        }
                    }
                    label { "Name" input type="text" name="name" value=(form.name) required maxlength="200"; }
                    div.radios {
                        label { input type="radio" name="kind" value="encrypt" checked[form.kind != "decrypt"]; " Encrypt files for partners" }
                        label { input type="radio" name="kind" value="decrypt" checked[form.kind == "decrypt"]; " Decrypt files from partners" }
                    }
                }
                fieldset {
                    legend { "Folders" }
                    p.hint { "Absolute paths on this server. The input and output folders must exist." }
                    label { "Input folder (watched)" input type="text" name="input" value=(form.input) required placeholder="/srv/sftp/acme/outbound"; }
                    label { "Output folder" input type="text" name="output" value=(form.output) required; }
                    label { "Processed files go to" input type="text" name="processed" value=(form.processed) placeholder="<input>/processed"; }
                    label.check { input type="checkbox" name="delete_processed" checked[form.delete_processed.is_some()]; " Delete source files after processing instead" }
                    label { "Failed files go to" input type="text" name="failed" value=(form.failed) placeholder="<input>/failed"; }
                    label { "Check every (seconds)" input type="number" name="interval" value=(form.interval) min=(jobs::MIN_POLL_INTERVAL_SECS); }
                }
                fieldset.encrypt-only {
                    legend { "Encryption" }
                    p { "Recipients" }
                    p.hint { "Every recipient can decrypt the output. Add one of your own keys to be able to read it yourself." }
                    (key_choices("recipients", data.keys.iter().filter(|k| (k.can_encrypt && usable(k)) || form.recipients.contains(&k.fingerprint)), &form.recipients))
                    label {
                        "Sign with"
                        select name="signer" {
                            option value="" { "Don't sign" }
                            @for key in data.keys.iter().filter(|k| (k.has_secret && k.can_sign && usable(k)) || form.signer == k.fingerprint) {
                                option value=(key.fingerprint) selected[form.signer == key.fingerprint] {
                                    (key.label()) " — " (key.customer_name) " — " (views::key_id(&key.fingerprint))
                                }
                            }
                        }
                    }
                    label.check { input type="checkbox" name="armor" checked[form.armor.is_some()]; " ASCII-armored output (.asc)" }
                    label { "Output extension" input type="text" name="extension" value=(form.extension) placeholder=".pgp, or .asc when armored" maxlength="20"; }
                    label.check {
                        input type="checkbox" name="seipd_v2" checked[form.seipd_v2.is_some()];
                        " Use SEIPD v2 (RFC 9580). Only for partners known to support it; GnuPG 2.4 and older cannot read it."
                    }
                }
                fieldset.decrypt-only {
                    legend { "Decryption" }
                    p { "Decrypt with" }
                    (key_choices("decrypt_keys", data.keys.iter().filter(|k| k.has_secret || form.decrypt_keys.contains(&k.fingerprint)), &form.decrypt_keys))
                    p { "Accept signatures from" }
                    (key_choices("verifiers", data.keys.iter().filter(|k| !k.revoked || form.verifiers.contains(&k.fingerprint)), &form.verifiers))
                    label {
                        "Signatures"
                        select name="verify" {
                            option value="ignore" selected[form.verify == "ignore"] { "Ignore" }
                            option value="warn" selected[form.verify == "warn"] { "Warn about unsigned or unverified files" }
                            option value="require" selected[form.verify == "require"] { "Require a valid signature (fail otherwise)" }
                        }
                    }
                }
                button.primary type="submit" {
                    @match target { FormTarget::Create => "Create job", FormTarget::Update(_) => "Save changes" }
                }
            }
        },
    )
}

fn key_choices<'a>(
    name: &str,
    keys: impl Iterator<Item = &'a KeyRecord>,
    selected: &[String],
) -> Markup {
    let keys: Vec<&KeyRecord> = keys.collect();
    html! {
        @if keys.is_empty() {
            p.muted { "No suitable keys. Add them on the customer's page." }
        } @else {
            div.choices {
                @for key in keys {
                    label.choice {
                        input type="checkbox" name=(name) value=(key.fingerprint) checked[selected.contains(&key.fingerprint)];
                        " " strong { (key.label()) }
                        " " span.muted { (key.customer_name) }
                        " " code.muted { (views::key_id(&key.fingerprint)) }
                        " " (views::key_status(key))
                    }
                }
            }
        }
    }
}

pub async fn list(State(state): State<AppState>, auth: Authed) -> Result<Markup, AppError> {
    let jobs = state.vault(|vault| vault.jobs()).await?;
    let page = state.page(&auth, "Jobs", Nav::Jobs);
    Ok(views::layout(
        page,
        html! {
            h1 { "Jobs" }
            @if jobs.is_empty() {
                p.muted { "No jobs yet." }
            } @else {
                table {
                    thead { tr { th { "Customer" } th { "Name" } th { "Kind" } th { "State" } th { "Input → output" } th { "Last run" } } }
                    tbody {
                        @for job in &jobs {
                            tr {
                                td { a href={ "/customers/" (job.customer_id) } { (job.customer_name) } }
                                td { a href={ "/jobs/" (job.id) } { (job.spec.name) } }
                                td { (views::kind_name(job)) }
                                td { (views::job_state(job)) }
                                td.paths { code { (job.spec.input_dir.display()) } " → " code { (job.spec.output_dir.display()) } }
                                td.nowrap { @match job.last_run_at { Some(at) => (views::timestamp(at)), None => span.muted { "never" } } }
                            }
                        }
                    }
                }
            }
            p { a.button href="/jobs/new" { "New job" } }
        },
    ))
}

#[derive(Deserialize)]
pub struct NewQuery {
    #[serde(default)]
    customer: String,
}

pub async fn new_form(
    State(state): State<AppState>,
    auth: Authed,
    Query(query): Query<NewQuery>,
) -> Result<Markup, AppError> {
    let data = form_data(&state).await?;
    let page = state.page(&auth, "New job", Nav::Jobs);
    let form = JobForm::blank(parse_id(&query.customer));
    Ok(form_page(page, &form, &data, FormTarget::Create, None))
}

pub async fn create(State(state): State<AppState>, posted: Posted<JobForm>) -> Response {
    let form = posted.form.clone();
    let outcome = async {
        let customer = form.customer_id()?;
        let spec = form.to_spec()?;
        state
            .vault(move |vault| vault.create_job(Actor::Admin, customer, &spec))
            .await
    }
    .await;
    match outcome {
        Ok(job) => state
            .done(
                &posted.auth,
                &format!("/jobs/{}", job.id),
                Ok(format!("Created job {}. It is running.", job.spec.name)),
            )
            .into_response(),
        Err(e) => rejected_form(&state, &posted.auth, &posted.form, FormTarget::Create, e).await,
    }
}

/// Show the form again, as filled in, with the reason it was rejected.
async fn rejected_form(
    state: &AppState,
    auth: &Authed,
    form: &JobForm,
    target: FormTarget<'_>,
    error: AppError,
) -> Response {
    let data = match form_data(state).await {
        Ok(data) => data,
        Err(e) => return e.into_response(),
    };
    let page = state.page(auth, "Job", Nav::Jobs);
    let status = if error.status.is_server_error() {
        error.status
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        form_page(page, form, &data, target, Some(error.message())),
    )
        .into_response()
}

pub async fn edit_form(
    State(state): State<AppState>,
    auth: Authed,
    Path(id): Path<i64>,
) -> Result<Markup, AppError> {
    let job = state.vault(move |vault| vault.job(id)).await?;
    let data = form_data(&state).await?;
    let page = state.page(&auth, &job.spec.name, Nav::Jobs);
    Ok(form_page(
        page,
        &JobForm::from_job(&job),
        &data,
        FormTarget::Update(&job),
        None,
    ))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    posted: Posted<JobForm>,
) -> Response {
    let job = match state.vault(move |vault| vault.job(id)).await {
        Ok(job) => job,
        Err(e) => return e.into_response(),
    };
    let outcome = async {
        let spec = posted.form.to_spec()?;
        state
            .vault(move |vault| vault.update_job(Actor::Admin, id, &spec))
            .await
    }
    .await;
    match outcome {
        Ok(job) => state
            .done(
                &posted.auth,
                &format!("/jobs/{id}"),
                Ok(format!("Saved job {}.", job.spec.name)),
            )
            .into_response(),
        Err(e) => {
            rejected_form(
                &state,
                &posted.auth,
                &posted.form,
                FormTarget::Update(&job),
                e,
            )
            .await
        }
    }
}

async fn failed_files(job: &Job) -> Result<Vec<FailedFile>, AppError> {
    let job = job.clone();
    tokio::task::spawn_blocking(move || failed::list(&job))
        .await
        .map_err(AppError::internal)?
        .map_err(|e| AppError::internal(format!("listing failed files: {e}")))
}

pub async fn show(
    State(state): State<AppState>,
    auth: Authed,
    Path(id): Path<i64>,
) -> Result<Markup, AppError> {
    let (job, events, customers, jobs) = state
        .vault(move |vault| {
            let events = vault.query_audit(&Filter {
                job_id: Some(id),
                limit: 20,
                ..Filter::default()
            })?;
            Ok((vault.job(id)?, events, vault.customers()?, vault.jobs()?))
        })
        .await?;
    let files = failed_files(&job).await?;
    let names = Names::new(&customers, &jobs);
    let csrf = auth.csrf.clone();
    let page = state.page(&auth, &job.spec.name, Nav::Jobs);
    let spec = &job.spec;
    let base = format!("/jobs/{}", job.id);
    Ok(views::layout(
        page,
        html! {
            p.crumbs { a href={ "/customers/" (job.customer_id) } { (job.customer_name) } " / jobs /" }
            h1 { (spec.name) }
            div.actions {
                @if job.is_active() {
                    form method="post" action={ (base) "/disable" } {
                        (views::csrf_field(&csrf))
                        button type="submit" { "Disable" }
                    }
                } @else {
                    form method="post" action={ (base) "/enable" } {
                        (views::csrf_field(&csrf))
                        button.primary type="submit" { @if job.paused_reason.is_some() { "Resume" } @else { "Enable" } }
                    }
                }
                a.button href={ (base) "/edit" } { "Edit" }
            }

            (live_panel(&csrf, &job, &files))

            section {
                h2 { "Settings" }
                dl.details {
                    dt { "Kind" } dd { (views::kind_name(&job)) }
                    dt { "Input" } dd { code { (spec.input_dir.display()) } }
                    dt { "Output" } dd { code { (spec.output_dir.display()) } }
                    dt { "Processed files" } dd {
                        @match &spec.processed_dir { Some(dir) => code { (dir.display()) }, None => "deleted" }
                    }
                    dt { "Failed files" } dd { code { (spec.failed_dir.display()) } }
                    dt { "Checks every" } dd { (spec.poll_interval_secs) " s" }
                    @match spec.kind {
                        JobKind::Encrypt => {
                            dt { "Recipients" } dd { @for fpr in &spec.recipients { div { a href={ "/keys/" (fpr) } { (views::fingerprint(fpr)) } } } }
                            dt { "Signed with" } dd {
                                @match &spec.signer { Some(fpr) => a href={ "/keys/" (fpr) } { (views::fingerprint(fpr)) }, None => span.muted { "not signed" } }
                            }
                            dt { "Format" } dd {
                                (if spec.container == Container::SeipdV2 { "SEIPD v2" } else { "SEIPD v1" }) ", "
                                (if spec.armor { "armored" } else { "binary" }) ", "
                                code { "*" (spec.output_extension()) }
                            }
                        }
                        JobKind::Decrypt => {
                            dt { "Decrypt with" } dd { @for fpr in &spec.decrypt_keys { div { a href={ "/keys/" (fpr) } { (views::fingerprint(fpr)) } } } }
                            dt { "Accept signatures from" } dd {
                                @if spec.verifiers.is_empty() { span.muted { "nobody" } }
                                @for fpr in &spec.verifiers { div { a href={ "/keys/" (fpr) } { (views::fingerprint(fpr)) } } }
                            }
                            dt { "Signatures" } dd { (policy_str(spec.verify_policy)) }
                        }
                    }
                    dt { "Created" } dd { (views::timestamp(job.created_at)) }
                    dt { "Last changed" } dd { (views::timestamp(job.updated_at)) }
                }
            }

            section {
                div.title-row {
                    h2 { "Recent activity" }
                    (views::activity_search(Some(("job", job.id.to_string()))))
                }
                (views::audit_table(&events, &names))
                p { a href={ "/audit?job=" (job.id) } { "All activity for this job →" } }
            }

            section.card.danger {
                h2 { "Delete job" }
                p { "Stops the job. Files and folders are left alone; the audit log is kept." }
                form.inline method="post" action={ (base) "/delete" } {
                    (views::csrf_field(&csrf))
                    (views::confirm_box("Delete this job"))
                    button.danger type="submit" { "Delete" }
                }
            }
        },
    ))
}

/// The self-refreshing status of a job.
pub async fn live(
    State(state): State<AppState>,
    Watching(auth): Watching,
    Path(id): Path<i64>,
) -> Result<Markup, AppError> {
    let job = state.vault(move |vault| vault.job(id)).await?;
    let files = failed_files(&job).await?;
    Ok(live_panel(&auth.csrf, &job, &files))
}

fn live_panel(csrf: &str, job: &Job, files: &[FailedFile]) -> Markup {
    html! {
        section #live.card hx-get={ "/jobs/" (job.id) "/live" } hx-trigger="every 5s" hx-swap="outerHTML" {
            h2 { "Status " (views::job_state(job)) }
            @if let Some(reason) = &job.paused_reason {
                p.flash.error { "Paused: " (reason) ". Fix the cause, then resume the job." }
            }
            dl.details {
                dt { "Last check" } dd { @match job.last_run_at { Some(at) => (views::timestamp(at)), None => span.muted { "never" } } }
                @if let Some(error) = &job.last_error {
                    dt { "Last error" } dd.error { (error) }
                }
            }
            h3 { "Failed files" }
            @if files.is_empty() {
                p.muted { "None." }
            } @else {
                p.hint { "The reason for each failure is in the activity log below. Retrying moves the file back into the input folder." }
                table {
                    thead { tr { th { "File" } th.num { "Size" } th { "Failed at" } th {} } }
                    tbody {
                        @for file in files {
                            tr {
                                td { code { (file.name) } }
                                td.num { (views::bytes(file.size)) }
                                td.nowrap {
                                    @if let Some(at) = file.modified.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()) {
                                        (views::timestamp(at.as_secs() as i64))
                                    }
                                }
                                td {
                                    form method="post" action={ "/jobs/" (job.id) "/retry" } {
                                        (views::csrf_field(csrf))
                                        input type="hidden" name="file" value=(file.name);
                                        button.small type="submit" { "Retry" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub async fn enable(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    posted: Posted<Empty>,
) -> Redirect {
    let outcome = state
        .vault(move |vault| vault.enable_job(Actor::Admin, id))
        .await
        .map(|job| format!("Job {} is running.", job.spec.name));
    state.done(&posted.auth, &format!("/jobs/{id}"), outcome)
}

pub async fn disable(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    posted: Posted<Empty>,
) -> Redirect {
    let outcome = state
        .vault(move |vault| vault.disable_job(Actor::Admin, id))
        .await
        .map(|job| format!("Job {} is disabled.", job.spec.name));
    state.done(&posted.auth, &format!("/jobs/{id}"), outcome)
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    posted: Posted<Confirmed>,
) -> Redirect {
    if let Err(e) = posted.form.check() {
        return state.done(&posted.auth, &format!("/jobs/{id}"), Err(e));
    }
    match state
        .vault(move |vault| vault.delete_job(Actor::Admin, id))
        .await
    {
        Ok(job) => state.done(
            &posted.auth,
            "/jobs",
            Ok(format!("Deleted job {}.", job.spec.name)),
        ),
        Err(e) => state.done(&posted.auth, &format!("/jobs/{id}"), Err(e)),
    }
}

#[derive(Deserialize)]
pub struct RetryForm {
    file: String,
}

pub async fn retry(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    posted: Posted<RetryForm>,
) -> Redirect {
    let name = posted.form.file.clone();
    let outcome = state
        .vault(move |vault| {
            let job = vault.job(id)?;
            Ok(failed::retry(vault, Actor::Admin, &job, &name))
        })
        .await
        .and_then(|moved| moved.map_err(AppError::bad_request))
        .map(|_| {
            format!(
                "Moved {} back to the input folder; it will be picked up on the next checks.",
                posted.form.file
            )
        });
    state.done(&posted.auth, &format!("/jobs/{id}"), outcome)
}
