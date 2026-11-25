use std::path::PathBuf;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use maud::{Markup, Render, html};
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
    ui::{self, Icon, Tone},
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
        parse_id(&self.customer)
            .ok_or_else(|| AppError::invalid_field("customer", "choose a customer"))
    }

    /// Turn the form into a spec. The vault does the real validation (folders, keys).
    fn to_spec(&self) -> Result<JobSpec, AppError> {
        let kind = match self.kind.as_str() {
            "encrypt" => JobKind::Encrypt,
            "decrypt" => JobKind::Decrypt,
            _ => return Err(AppError::invalid_field("kind", "choose encrypt or decrypt")),
        };
        let folder = |value: &str, label: &'static str| {
            let value = value.trim();
            if value.is_empty() {
                Err(AppError::invalid_field(
                    label,
                    format!("the {label} folder is required"),
                ))
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
                AppError::invalid_field(
                    "interval",
                    "the polling interval must be a whole number of seconds",
                )
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
    error: Option<&AppError>,
) -> Markup {
    let csrf = page.csrf.to_owned();
    let (heading, action, back) = match &target {
        FormTarget::Create => ("New job".to_owned(), "/jobs".to_owned(), "/jobs".to_owned()),
        FormTarget::Update(job) => (
            format!("Edit job {}", job.spec.name),
            format!("/jobs/{}", job.id),
            format!("/jobs/{}", job.id),
        ),
    };
    let usable = |key: &KeyRecord| jobs::usable(key).is_ok();
    let min_interval = jobs::MIN_POLL_INTERVAL_SECS.to_string();
    // The server's complaint about one field, shown next to it.
    let blamed = error.and_then(|e| e.field().map(|field| (field, e.message())));
    let problem = |name: &str| blamed.filter(|(field, _)| *field == name).map(|(_, m)| m);
    let invalid = |name: &str| problem(name).map(|_| "true");
    let described = |name: &str| problem(name).map(|_| ui::error_id(name));
    views::layout(
        page,
        html! {
            (ui::page_header(&heading)
                .crumb("Jobs", "/jobs")
                .subtitle(html! { "A job watches an input folder and encrypts or decrypts every file that arrives into the output folder." }))
            @if let Some(error) = error {
                (ui::alert(Tone::Bad, Some("The job was not saved"), html! {
                    @match blamed {
                        Some((field, message)) => a href={ "#" (ui::error_id(field)) } { (message) },
                        None => (error.message()),
                    }
                }))
            }
            form.form.job-form method="post" action=(action) {
                (views::csrf_field(&csrf))
                (ui::panel(html! {
                    div.form {
                        @match &target {
                            FormTarget::Create => {
                                (ui::form_field("Customer", html! {
                                    select name="customer" required aria-invalid=[invalid("customer")] aria-describedby=[described("customer")] {
                                        option value="" { "Choose…" }
                                        @for customer in &data.customers {
                                            option value=(customer.id) selected[form.customer == customer.id.to_string()] { (customer.name) }
                                        }
                                    }
                                }).error("customer", problem("customer")))
                            }
                            FormTarget::Update(job) => {
                                p { "Customer: " strong { (job.customer_name) } }
                            }
                        }
                        (ui::form_field("Name", html! {
                            input type="text" name="name" value=(form.name) required maxlength="200"
                                aria-invalid=[invalid("name")] aria-describedby=[described("name")];
                        }).hint(Some("Short and specific, like daily-orders.")).error("name", problem("name")))
                        (ui::form_field("Kind of job", html! {
                            div.choice-cards {
                                (ui::choice_card("kind", "encrypt", form.kind != "decrypt", "Encrypt", "Files for partners: encrypt to their keys, optionally sign with ours."))
                                (ui::choice_card("kind", "decrypt", form.kind == "decrypt", "Decrypt", "Files from partners: decrypt with our keys, optionally check their signature."))
                            }
                        }).group().error("kind", problem("kind")))
                    }
                }).title("Job").step(1))

                (ui::panel(html! {
                    div.form {
                        div.form-row {
                            (ui::form_field("Input folder (watched)", html! {
                                input type="text" name="input" value=(form.input) required placeholder=(jobs::FOLDER_EXAMPLES.input)
                                    aria-invalid=[invalid("input")] aria-describedby=[described("input")];
                            }).error("input", problem("input")))
                            (ui::form_field("Output folder", html! {
                                input type="text" name="output" value=(form.output) required placeholder=(jobs::FOLDER_EXAMPLES.output)
                                    aria-invalid=[invalid("output")] aria-describedby=[described("output")];
                            }).error("output", problem("output")))
                        }
                        div.form-row {
                            (ui::form_field("Processed files go to", html! {
                                input type="text" name="processed" value=(form.processed) placeholder=(jobs::FOLDER_EXAMPLES.processed)
                                    aria-invalid=[invalid("processed")] aria-describedby=[described("processed")];
                            }).optional().error("processed", problem("processed")))
                            (ui::form_field("Failed files go to", html! {
                                input type="text" name="failed" value=(form.failed) placeholder=(jobs::FOLDER_EXAMPLES.failed)
                                    aria-invalid=[invalid("failed")] aria-describedby=[described("failed")];
                            }).optional().error("failed", problem("failed")))
                        }
                        (ui::checkbox("delete_processed", form.delete_processed.is_some(), "Delete source files after processing instead of archiving them", None))
                        div.form-row {
                            (ui::form_field("Check every (seconds)", html! {
                                input type="number" name="interval" value=(form.interval) min=(min_interval)
                                    aria-invalid=[invalid("interval")] aria-describedby=[described("interval")];
                            }).error("interval", problem("interval")))
                        }
                    }
                })
                .title("Folders")
                .step(2)
                .description(html! { "Absolute paths on this server. The input and output folders must exist." }))

                div.encrypt-only {
                    (ui::panel(html! {
                        div.form {
                            (ui::form_field("Recipients",
                                key_choices("recipients", data.keys.iter().filter(|k| (k.can_encrypt && usable(k)) || form.recipients.contains(&k.fingerprint)), &form.recipients))
                                .hint(Some("Every recipient can decrypt the output. Add one of your own keys to be able to read it yourself."))
                                .group()
                                .error("recipients", problem("recipients")))
                            (ui::form_field("Sign with", html! {
                                select name="signer" aria-invalid=[invalid("signer")] aria-describedby=[described("signer")] {
                                    option value="" { "Don't sign" }
                                    @for key in data.keys.iter().filter(|k| (k.has_secret && k.can_sign && usable(k)) || form.signer == k.fingerprint) {
                                        option value=(key.fingerprint) selected[form.signer == key.fingerprint] {
                                            (key.label()) " — " (views::owner_name(key)) " — " (views::key_id(&key.fingerprint))
                                        }
                                    }
                                }
                            }).error("signer", problem("signer")))
                            div.form-row {
                                (ui::form_field("Output extension", html! {
                                    input type="text" name="extension" value=(form.extension) placeholder=".pgp, or .asc when armored" maxlength="20"
                                        aria-invalid=[invalid("extension")] aria-describedby=[described("extension")];
                                }).optional().error("extension", problem("extension")))
                            }
                            (ui::checkbox("armor", form.armor.is_some(), "ASCII-armored output (.asc)", None))
                            (ui::checkbox("seipd_v2", form.seipd_v2.is_some(), "Use SEIPD v2 (RFC 9580)",
                                Some("Only for partners known to support it; GnuPG 2.4 and older cannot read it.")))
                        }
                    }).title("Encryption").step(3))
                }
                div.decrypt-only {
                    (ui::panel(html! {
                        div.form {
                            (ui::form_field("Decrypt with",
                                key_choices("decrypt_keys", data.keys.iter().filter(|k| k.has_secret || form.decrypt_keys.contains(&k.fingerprint)), &form.decrypt_keys))
                                .group()
                                .error("decrypt_keys", problem("decrypt_keys")))
                            (ui::form_field("Accept signatures from",
                                key_choices("verifiers", data.keys.iter().filter(|k| !k.revoked || form.verifiers.contains(&k.fingerprint)), &form.verifiers))
                                .group()
                                .error("verifiers", problem("verifiers")))
                            (ui::field("Signatures", None, html! {
                                select name="verify" {
                                    option value="ignore" selected[form.verify == "ignore"] { "Ignore" }
                                    option value="warn" selected[form.verify == "warn"] { "Warn about unsigned or unverified files" }
                                    option value="require" selected[form.verify == "require"] { "Require a valid signature (fail otherwise)" }
                                }
                            }))
                        }
                    }).title("Decryption").step(3))
                }
                div.btn-row {
                    (ui::button(match target { FormTarget::Create => "Create job", FormTarget::Update(_) => "Save changes" }).primary().icon(Icon::Check).busy("Saving…"))
                    (ui::button("Cancel").ghost().href(&back))
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
            p.hint { "No suitable keys. Add them on the " a href="/keys" { "Keys" } " page." }
        } @else {
            div.choices {
                @for key in keys {
                    label.check {
                        input type="checkbox" name=(name) value=(key.fingerprint) checked[selected.contains(&key.fingerprint)];
                        span.check-body {
                            strong { (key.label()) }
                            span.muted { (views::owner_name(key)) }
                            code { (views::key_id(&key.fingerprint)) }
                            (views::key_status(key))
                        }
                    }
                }
            }
        }
    }
}

/// Jobs as a table; `with_customer` adds the customer column.
pub fn job_table(jobs: &[Job], with_customer: bool) -> Markup {
    let mut columns = vec![ui::col("Job")];
    if with_customer {
        columns.push(ui::col("Customer"));
    }
    columns.extend([
        ui::col("Kind"),
        ui::col("State"),
        ui::col("Input → output"),
        ui::col("Last check"),
    ]);
    ui::table(
        "",
        &columns,
        html! {
            @for job in jobs {
                tr {
                    td { a.strong href={ "/jobs/" (job.id) } { (job.spec.name) } }
                    @if with_customer {
                        td { a href={ "/customers/" (job.customer_id) } { (job.customer_name) } }
                    }
                    td { (views::kind_tag(job)) }
                    td { (views::job_state(job)) }
                    td.paths { code { (job.spec.input_dir.display()) } " → " code { (job.spec.output_dir.display()) } }
                    td.nowrap { @match job.last_run_at { Some(at) => (views::timestamp(at)), None => span.muted { "never" } } }
                }
            }
        },
    )
}

pub async fn list(State(state): State<AppState>, auth: Authed) -> Result<Markup, AppError> {
    let jobs = state.vault(|vault| vault.jobs()).await?;
    let page = state.page(&auth, "Jobs", Nav::Jobs);
    let running = jobs.iter().filter(|j| j.is_active()).count();
    Ok(views::layout(
        page,
        html! {
            (ui::page_header("Jobs")
                .subtitle(html! { (running) " of " (jobs.len()) " running. Each job watches a folder and encrypts or decrypts what arrives." })
                .actions(html! { (ui::button("New job").primary().icon(Icon::Plus).href("/jobs/new")) }))
            (ui::panel(html! {
                @if jobs.is_empty() {
                    (ui::empty(Icon::Jobs, "No jobs yet", "Create a job to encrypt files for a partner, or decrypt the files they send.",
                        Some(ui::button("New job").primary().icon(Icon::Plus).href("/jobs/new").render())))
                } @else {
                    (job_table(&jobs, true))
                }
            }).flush())
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
    (status, form_page(page, form, &data, target, Some(&error))).into_response()
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
    let (job, events, customers, jobs, keys) = state
        .vault(move |vault| {
            let events = vault.query_audit(&Filter {
                job_id: Some(id),
                limit: 20,
                ..Filter::default()
            })?;
            Ok((
                vault.job(id)?,
                events,
                vault.customers()?,
                vault.jobs()?,
                vault.keys(None)?,
            ))
        })
        .await?;
    let files = failed_files(&job).await?;
    let names = Names::new(&customers, &jobs);
    let csrf = auth.csrf.clone();
    let page = state.page(&auth, &job.spec.name, Nav::Jobs);
    let spec = &job.spec;
    let base = format!("/jobs/{}", job.id);
    let edit = format!("{base}/edit");
    let customer_url = format!("/customers/{}", job.customer_id);
    let all_activity = format!("/audit?job={}", job.id);
    let key = |fpr: &String| -> Markup {
        match keys.iter().find(|k| k.fingerprint == *fpr) {
            Some(k) => html! { div { (views::key_link(k)) " " (views::key_status(k)) } },
            None => html! { div { code { (views::key_id(fpr)) } } },
        }
    };
    Ok(views::layout(
        page,
        html! {
            (ui::page_header(&spec.name)
                .crumb("Customers", "/customers")
                .crumb(&job.customer_name, customer_url)
                .status(views::kind_tag(&job))
                .subtitle(html! {
                    (if spec.kind == JobKind::Encrypt { "Encrypts" } else { "Decrypts" })
                    " every file dropped into its input folder; checks every " (spec.poll_interval_secs) " seconds."
                })
                .actions(html! {
                    @if job.is_active() {
                        form method="post" action={ (base) "/disable" } {
                            (views::csrf_field(&csrf))
                            (ui::button("Disable").icon(Icon::Pause))
                        }
                    } @else {
                        form method="post" action={ (base) "/enable" } {
                            (views::csrf_field(&csrf))
                            (ui::button(if job.paused_reason.is_some() { "Resume" } else { "Enable" }).primary().icon(Icon::Play))
                        }
                    }
                    (ui::button("Edit").icon(Icon::Edit).href(&edit))
                }))

            (live_panel(&csrf, &job, &files))

            div.grid-2 {
                (ui::panel(html! {
                    dl.kv {
                        dt { "Input" } dd { code { (spec.input_dir.display()) } }
                        dt { "Output" } dd { code { (spec.output_dir.display()) } }
                        dt { "Processed files" } dd {
                            @match &spec.processed_dir { Some(dir) => code { (dir.display()) }, None => "deleted" }
                        }
                        dt { "Failed files" } dd { code { (spec.failed_dir.display()) } }
                        dt { "Checks every" } dd { (spec.poll_interval_secs) " s" }
                        dt { "Created" } dd { (views::timestamp(job.created_at)) }
                        dt { "Last changed" } dd { (views::timestamp(job.updated_at)) }
                    }
                }).title("Folders").icon(Icon::Jobs))
                (ui::panel(html! {
                    dl.kv {
                        @match spec.kind {
                            JobKind::Encrypt => {
                                dt { "Recipients" } dd { @for fpr in &spec.recipients { (key(fpr)) } }
                                dt { "Signed with" } dd {
                                    @match &spec.signer { Some(fpr) => (key(fpr)), None => span.muted { "not signed" } }
                                }
                                dt { "Format" } dd {
                                    (if spec.container == Container::SeipdV2 { "SEIPD v2" } else { "SEIPD v1" }) ", "
                                    (if spec.armor { "armored" } else { "binary" }) ", "
                                    code { "*" (spec.output_extension()) }
                                }
                            }
                            JobKind::Decrypt => {
                                dt { "Decrypt with" } dd { @for fpr in &spec.decrypt_keys { (key(fpr)) } }
                                dt { "Signatures from" } dd {
                                    @if spec.verifiers.is_empty() { span.muted { "nobody" } }
                                    @for fpr in &spec.verifiers { (key(fpr)) }
                                }
                                dt { "Signatures" } dd { (policy_str(spec.verify_policy)) }
                            }
                        }
                    }
                }).title("Keys").icon(Icon::Key))
            }

            (ui::panel(views::audit_table(&events, &names))
                .title("Recent activity")
                .icon(Icon::Activity)
                .actions(views::activity_search(Some(("job", job.id.to_string()))))
                .flush()
                .footer(ui::link_arrow(&all_activity, "All activity for this job")))

            (ui::panel(html! {
                p { "Stops the job. Files and folders are left alone; the audit log is kept." }
                form.form method="post" action={ (base) "/delete" } data-confirm="The job stops for good. Its files, folders and audit log stay." {
                    (views::csrf_field(&csrf))
                    (ui::confirm("Delete this job"))
                    div.actions { (ui::button("Delete job").danger().icon(Icon::Trash)) }
                }
            }).title("Delete job").icon(Icon::Trash).tone(Tone::Bad))
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
    let url = format!("/jobs/{}/live", job.id);
    let retry = format!("/jobs/{}/retry", job.id);
    let body = html! {
        (ui::panel_section(html! {
            @if let Some(reason) = &job.paused_reason {
                (ui::alert(Tone::Bad, Some("Paused"), html! { (reason) ". Fix the cause, then resume the job." }))
            }
            dl.kv {
                dt { "State" } dd { (views::job_state(job)) }
                dt { "Last check" } dd { @match job.last_run_at { Some(at) => (views::timestamp(at)), None => span.muted { "never" } } }
                @if let Some(error) = &job.last_error {
                    dt { "Last error" } dd.error-text { (error) }
                }
            }
        }))
        @if !files.is_empty() {
            (ui::table("", &[ui::col("Failed file"), ui::num_col("Size"), ui::col("Failed at"), ui::num_col("")], html! {
                @for file in files {
                    tr.bad {
                        td { code { (file.name) } }
                        td.num { (views::bytes(file.size)) }
                        td.nowrap {
                            @if let Some(at) = file.modified.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()) {
                                (views::timestamp(at.as_secs() as i64))
                            }
                        }
                        td.num {
                            form method="post" action=(retry) {
                                (views::csrf_field(csrf))
                                input type="hidden" name="file" value=(file.name);
                                (ui::button("Retry").small().icon(Icon::Retry))
                            }
                        }
                    }
                }
            }))
        }
    };
    let footer = html! {
        @if files.is_empty() {
            span.btn-row { (ui::icon_with(Icon::Check, "icon sm")) "No failed files." }
        } @else {
            "The reason for each failure is in the activity below. Retrying moves the file back into the input folder."
        }
    };
    ui::panel(body)
        .title("Status")
        .icon(Icon::Activity)
        .flush()
        .footer(footer)
        .id("live")
        .live(&url, 5)
        .render()
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
