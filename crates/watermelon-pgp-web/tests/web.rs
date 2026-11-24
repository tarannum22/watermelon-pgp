//! The web UI end to end, in process: requests go straight into the router.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use watermelon_pgp_core::{
    audit::Actor,
    crypto::{self, Algorithm},
    envelope::MasterKey,
    vault::{self, Vault},
};
use watermelon_pgp_web::{AppState, Config, SESSION_COOKIE, router};

const PASSWORD: &str = "a long admin password";

struct App {
    dir: tempfile::TempDir,
    router: Router,
    vault: Arc<Mutex<Vault>>,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn location(&self) -> &str {
        self.headers
            .get(header::LOCATION)
            .map_or("", |v| v.to_str().unwrap())
    }
}

/// A logged-in browser.
struct Session {
    cookie: String,
    csrf: String,
}

impl App {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(vault::MASTER_KEY_FILE);
        let report = Vault::init(&dir.path().join("data"), &key_path, PASSWORD).unwrap();
        let vault = Vault::open(&report.db_path, MasterKey::load(&key_path).unwrap()).unwrap();
        let vault = Arc::new(Mutex::new(vault));
        let router = router(AppState::new(Arc::clone(&vault), Config::default()));
        Self { dir, router, vault }
    }

    async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn get(&self, path: &str, session: Option<&Session>) -> Reply {
        let mut request = Request::get(path);
        if let Some(session) = session {
            request = request.header(header::COOKIE, &session.cookie);
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    async fn post(&self, path: &str, session: Option<&Session>, form: &str) -> Reply {
        let mut request = Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::HOST, "localhost:8080")
            .header(header::ORIGIN, "http://localhost:8080");
        if let Some(session) = session {
            request = request.header(header::COOKIE, &session.cookie);
        }
        self.send(request.body(Body::from(form.to_owned())).unwrap())
            .await
    }

    /// Post a form with the session's CSRF token added.
    async fn submit(&self, path: &str, session: &Session, form: &str) -> Reply {
        let form = if form.is_empty() {
            format!("_csrf={}", session.csrf)
        } else {
            format!("_csrf={}&{form}", session.csrf)
        };
        self.post(path, Some(session), &form).await
    }

    async fn login(&self) -> Session {
        let reply = self
            .post("/login", None, &format!("password={}", enc(PASSWORD)))
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        let set_cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
        assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"));
        let cookie = set_cookie.split(';').next().unwrap().to_owned();
        let mut session = Session {
            cookie,
            csrf: String::new(),
        };
        let page = self.get("/", Some(&session)).await;
        assert_eq!(page.status, StatusCode::OK);
        session.csrf = csrf_token(&page.body);
        session
    }

    /// Follow a form's redirect and return the page it lands on.
    async fn follow(&self, reply: Reply, session: &Session) -> Reply {
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        self.get(reply.location(), Some(session)).await
    }

    fn vault(&self) -> std::sync::MutexGuard<'_, Vault> {
        self.vault.lock().unwrap()
    }

    fn actions(&self) -> Vec<String> {
        self.vault()
            .audit_events(200)
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect()
    }

    fn folder(&self, name: &str) -> String {
        let dir = self.dir.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        dir.display().to_string()
    }
}

fn csrf_token(html: &str) -> String {
    let marker = r#"name="_csrf" value=""#;
    let start = html.find(marker).expect("page has a CSRF field") + marker.len();
    html[start..start + 64].to_owned()
}

fn enc(value: &str) -> String {
    serde_html_form::to_string([("v", value)]).unwrap()[2..].to_owned()
}

#[tokio::test]
async fn health_and_assets_are_public() {
    let app = App::new();
    let health = app.get("/healthz", None).await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.body, r#"{"status":"ok"}"#);

    for asset in [
        "htmx.min.js",
        "app.js",
        "app.css",
        "logo.svg",
        "geist-1.9.0.woff2",
        "jetbrains-mono-5.3.0.woff2",
    ] {
        let reply = app.get(&format!("/static/{asset}"), None).await;
        assert_eq!(reply.status, StatusCode::OK, "{asset}");
        assert!(
            reply.headers[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("immutable")
        );
    }
    assert_eq!(
        app.get("/static/../Cargo.toml", None).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn pages_require_login() {
    let app = App::new();
    for path in ["/", "/customers", "/keys", "/jobs", "/audit", "/settings"] {
        let reply = app.get(path, None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(reply.location(), "/login");
    }
    let htmx = app
        .send(
            Request::get("/dashboard/live")
                .header("hx-request", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(htmx.headers["hx-redirect"], "/login");

    let forged = app
        .get(
            "/",
            Some(&Session {
                cookie: format!("{SESSION_COOKIE}={}", "ab".repeat(32)),
                csrf: String::new(),
            }),
        )
        .await;
    assert_eq!(forged.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn pages_carry_security_headers() {
    let app = App::new();
    let session = app.login().await;
    let page = app.get("/", Some(&session)).await;
    let csp = page.headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(page.headers[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(page.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    assert!(!page.body.contains("<script>"), "no inline scripts");
}

#[tokio::test]
async fn wrong_passwords_are_audited_and_rate_limited() {
    let app = App::new();
    for _ in 0..5 {
        let reply = app.post("/login", None, "password=wrong").await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert!(reply.body.contains("Wrong password"));
    }
    let locked = app
        .post("/login", None, &format!("password={}", enc(PASSWORD)))
        .await;
    assert_eq!(
        locked.status,
        StatusCode::TOO_MANY_REQUESTS,
        "even the right password waits"
    );
    let failures = app
        .actions()
        .iter()
        .filter(|a| *a == "admin.login_failed")
        .count();
    assert_eq!(failures, 5);
}

#[tokio::test]
async fn forms_need_the_csrf_token_and_same_origin() {
    let app = App::new();
    let session = app.login().await;

    let no_token = app.post("/customers", Some(&session), "name=ACME").await;
    assert_eq!(no_token.status, StatusCode::FORBIDDEN);
    let wrong_token = app
        .post(
            "/customers",
            Some(&session),
            &format!("_csrf={}&name=ACME", "0".repeat(64)),
        )
        .await;
    assert_eq!(wrong_token.status, StatusCode::FORBIDDEN);

    let cross_origin = app
        .send(
            Request::post("/customers")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::HOST, "localhost:8080")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::COOKIE, &session.cookie)
                .body(Body::from(format!("_csrf={}&name=ACME", session.csrf)))
                .unwrap(),
        )
        .await;
    assert_eq!(cross_origin.status, StatusCode::FORBIDDEN);
    assert!(app.vault().customers().unwrap().is_empty());

    // HTTP/2 has no Host header: the authority is part of the request URI.
    let http2 = app
        .send(
            Request::post("https://localhost:8443/customers")
                .version(axum::http::Version::HTTP_2)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, "https://localhost:8443")
                .header(header::COOKIE, &session.cookie)
                .body(Body::from(format!("_csrf={}&name=Globex", session.csrf)))
                .unwrap(),
        )
        .await;
    assert_eq!(http2.status, StatusCode::SEE_OTHER, "{}", http2.body);

    let ok = app.submit("/customers", &session, "name=ACME").await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER);
    assert_eq!(app.vault().customers().unwrap().len(), 2);
}

#[tokio::test]
async fn logout_ends_the_session() {
    let app = App::new();
    let session = app.login().await;
    let reply = app.submit("/logout", &session, "").await;
    assert_eq!(reply.location(), "/login");
    assert!(
        reply.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        app.get("/", Some(&session)).await.status,
        StatusCode::SEE_OTHER
    );
    let actions = app.actions();
    assert_eq!(actions[0], "admin.logout");
    assert_eq!(actions[1], "admin.login");
}

#[tokio::test]
async fn customer_and_key_lifecycle() {
    let app = App::new();
    let session = app.login().await;

    let page = app
        .follow(
            app.submit("/customers", &session, "name=ACME").await,
            &session,
        )
        .await;
    assert!(page.body.contains("Created customer ACME"), "flash shown");
    let customer = app.vault().customer("ACME").unwrap().id;

    // Generate.
    let page = app
        .follow(
            app.submit(
                &format!("/customers/{customer}/keys/generate"),
                &session,
                &format!(
                    "user_id={}&algorithm=curve25519",
                    enc("ACME <pgp@acme.example>")
                ),
            )
            .await,
            &session,
        )
        .await;
    assert!(page.body.contains("Generated key ACME"), "{}", page.body);
    let key = app.vault().keys(Some(customer)).unwrap().remove(0);
    assert!(key.has_secret);

    let detail = app
        .get(&format!("/keys/{}", key.fingerprint), Some(&session))
        .await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.body.contains("Export secret key"));

    // Public export is a download.
    let public = app
        .submit(&format!("/keys/{}/public", key.fingerprint), &session, "")
        .await;
    assert_eq!(public.status, StatusCode::OK);
    assert!(
        public
            .body
            .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    );
    assert!(
        public.headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains("attachment; filename=\"ACME-")
    );

    // Secret export needs matching passphrases of a minimum length.
    let path = format!("/keys/{}/secret", key.fingerprint);
    let short = app
        .follow(
            app.submit(&path, &session, "passphrase=short&repeat=short")
                .await,
            &session,
        )
        .await;
    assert!(short.body.contains("at least 8 characters"));
    let secret = app
        .submit(
            &path,
            &session,
            "passphrase=export-passphrase&repeat=export-passphrase",
        )
        .await;
    assert_eq!(secret.status, StatusCode::OK);
    assert!(
        secret
            .body
            .starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    );
    assert!(app.actions().contains(&"key.export_secret".to_owned()));

    // The export opens with its passphrase and imports into another customer... but the key
    // already exists, which the import reports.
    let mut certs = crypto::parse_certs(secret.body.as_bytes()).unwrap();
    assert!(certs[0].is_locked());
    certs[0].unlock("export-passphrase").unwrap();

    // Revoke, with confirmation.
    let revoke = format!("/keys/{}/revoke", key.fingerprint);
    let refused = app
        .follow(
            app.submit(&revoke, &session, "reason=retired").await,
            &session,
        )
        .await;
    assert!(refused.body.contains("tick the confirmation box"));
    let revoked = app
        .follow(
            app.submit(&revoke, &session, "reason=retired&comment=test&confirm=yes")
                .await,
            &session,
        )
        .await;
    assert!(revoked.body.contains("Revoked key"), "{}", revoked.body);
    assert!(app.vault().find_key(&key.fingerprint).unwrap().revoked);
    assert!(
        !revoked.body.contains("Revoke this key permanently"),
        "form gone"
    );

    // Delete needs the confirmation box.
    let delete = format!("/keys/{}/delete", key.fingerprint);
    let refused = app
        .follow(app.submit(&delete, &session, "").await, &session)
        .await;
    assert!(refused.body.contains("tick the confirmation box"));
    let deleted = app
        .follow(app.submit(&delete, &session, "confirm=yes").await, &session)
        .await;
    assert!(deleted.body.contains("Deleted key"));
    assert!(app.vault().keys(Some(customer)).unwrap().is_empty());
}

#[tokio::test]
async fn keys_can_be_generated_from_the_keys_page() {
    let app = App::new();
    let session = app.login().await;
    let acme = app.vault().create_customer(Actor::Cli, "Acme").unwrap();
    let page = app.get("/keys", Some(&session)).await;
    assert!(page.body.contains(r#"action="/keys/generate""#));
    assert!(
        page.body
            .contains(r#"<option value="none">No customer (anonymous key)</option>"#)
    );
    assert!(
        page.body
            .contains(&format!(r#"<option value="{}">Acme</option>"#, acme.id))
    );

    // A choice must be made: a customer, or explicitly none.
    for bad in ["", "999"] {
        let reply = app
            .submit(
                "/keys/generate",
                &session,
                &format!("customer={bad}&user_id=X&algorithm=curve25519"),
            )
            .await;
        assert_eq!(reply.location(), "/keys", "{bad:?}");
    }
    assert!(app.vault().keys(None).unwrap().is_empty());

    // For a customer: the new key's page opens.
    let reply = app
        .submit(
            "/keys/generate",
            &session,
            &format!(
                "customer={}&user_id={}&algorithm=curve25519",
                acme.id,
                enc("Acme Exports <exports@acme.example>")
            ),
        )
        .await;
    let keys = app.vault().keys(Some(acme.id)).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(reply.location(), format!("/keys/{}", keys[0].fingerprint));
    let page = app.follow(reply, &session).await;
    assert!(page.body.contains("Generated key Acme Exports"));

    // Anonymous: no customer.
    let reply = app
        .submit(
            "/keys/generate",
            &session,
            &format!(
                "customer=none&user_id={}&algorithm=curve25519",
                enc("Ops <ops@example.com>")
            ),
        )
        .await;
    let anonymous: Vec<_> = app
        .vault()
        .keys(None)
        .unwrap()
        .into_iter()
        .filter(|k| k.customer_id.is_none())
        .collect();
    assert_eq!(anonymous.len(), 1);
    let page = app.follow(reply, &session).await;
    assert!(
        page.body
            .contains(r#"title="belongs to no customer">anonymous</span>"#)
    );
    assert!(
        page.body.contains(r#"<a href="/keys">Keys</a>"#),
        "breadcrumb to the key list"
    );
    let list = app.get("/keys?show=anonymous", Some(&session)).await;
    assert!(list.body.contains("Ops") && !list.body.contains("Acme Exports"));

    // Like every form, it needs the CSRF token.
    let reply = app
        .post(
            "/keys/generate",
            Some(&session),
            "customer=none&user_id=Y&algorithm=curve25519",
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn keys_can_be_imported_by_upload() {
    let app = App::new();
    let session = app.login().await;
    let customer = app.vault().create_customer(Actor::Cli, "ACME").unwrap().id;
    let partner = crypto::generate("Partner <p@example.com>", Algorithm::Curve25519).unwrap();
    let protected = crypto::armor_secret(&partner, "partner-pass").unwrap();

    let multipart = |passphrase: &str| {
        let boundary = "XBOUNDARY";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n{}\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"armored\"\r\n\r\n{protected}\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"passphrase\"\r\n\r\n{passphrase}\r\n\
             --{boundary}--\r\n",
            session.csrf
        );
        Request::post(format!("/customers/{customer}/keys/import"))
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header(header::COOKIE, &session.cookie)
            .body(Body::from(body))
            .unwrap()
    };

    let wrong = app
        .follow(app.send(multipart("nope")).await, &session)
        .await;
    assert!(wrong.body.contains("wrong passphrase"), "{}", wrong.body);
    let ok = app
        .follow(app.send(multipart("partner-pass")).await, &session)
        .await;
    assert!(
        ok.body.contains("Imported or updated Partner"),
        "{}",
        ok.body
    );
    let keys = app.vault().keys(Some(customer)).unwrap();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].has_secret);
}

#[tokio::test]
async fn jobs_are_created_edited_and_controlled_from_forms() {
    let app = App::new();
    let session = app.login().await;
    let (customer, ours, partner) = {
        let vault = app.vault();
        let customer = vault.create_customer(Actor::Cli, "ACME").unwrap().id;
        let ours = vault
            .generate_key(Actor::Cli, customer, "Ours", Algorithm::Curve25519)
            .unwrap()
            .fingerprint;
        let partner = crypto::generate("Partner", Algorithm::Curve25519).unwrap();
        let armored = crypto::armor_public(&partner.to_public_key()).unwrap();
        let partner = vault
            .import_keys(Actor::Cli, customer, armored.as_bytes(), None)
            .unwrap()
            .remove(0)
            .fingerprint;
        (customer, ours, partner)
    };
    let (input, output) = (app.folder("in"), app.folder("out"));

    let form = app
        .get(&format!("/jobs/new?customer={customer}"), Some(&session))
        .await;
    assert!(form.body.contains(&partner), "recipient offered");

    // Rejected forms come back filled in, with the reason.
    let fields = format!(
        "customer={customer}&name=outbound&kind=encrypt&input={}&output={}&interval=30&signer={ours}",
        enc(&input),
        enc(&output)
    );
    let rejected = app.submit("/jobs", &session, &fields).await;
    assert_eq!(rejected.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(rejected.body.contains("at least one recipient"));
    assert!(rejected.body.contains(r#"value="outbound""#), "values kept");

    let fields = format!("{fields}&recipients={partner}&recipients={ours}&armor=on");
    let created = app.submit("/jobs", &session, &fields).await;
    let page = app.follow(created, &session).await;
    assert!(page.body.contains("Created job outbound"), "{}", page.body);
    let job = app.vault().find_job("outbound").unwrap();
    assert_eq!(job.spec.recipients, vec![partner.clone(), ours.clone()]);
    assert_eq!(job.spec.signer.as_deref(), Some(ours.as_str()));
    assert!(job.spec.armor);

    // Edit: the form starts from the stored job.
    let edit = app
        .get(&format!("/jobs/{}/edit", job.id), Some(&session))
        .await;
    assert!(edit.body.contains(r#"value="outbound""#));
    let changed = fields
        .replace("interval=30", "interval=90")
        .replace("&armor=on", "");
    app.follow(
        app.submit(&format!("/jobs/{}", job.id), &session, &changed)
            .await,
        &session,
    )
    .await;
    let job = app.vault().job(job.id).unwrap();
    assert_eq!(job.spec.poll_interval_secs, 90);
    assert!(!job.spec.armor);

    // Disable, enable, live panel.
    app.submit(&format!("/jobs/{}/disable", job.id), &session, "")
        .await;
    assert!(!app.vault().job(job.id).unwrap().enabled);
    app.submit(&format!("/jobs/{}/enable", job.id), &session, "")
        .await;
    assert!(app.vault().job(job.id).unwrap().is_active());
    let live = app
        .get(&format!("/jobs/{}/live", job.id), Some(&session))
        .await;
    assert!(live.body.contains("No failed files."));

    // A failed file can be retried from the page.
    std::fs::create_dir_all(&job.spec.failed_dir).unwrap();
    std::fs::write(job.spec.failed_dir.join("broken.csv"), "x").unwrap();
    let show = app.get(&format!("/jobs/{}", job.id), Some(&session)).await;
    assert!(show.body.contains("broken.csv"));
    let retried = app
        .follow(
            app.submit(
                &format!("/jobs/{}/retry", job.id),
                &session,
                "file=broken.csv",
            )
            .await,
            &session,
        )
        .await;
    assert!(retried.body.contains("Moved broken.csv back"));
    assert!(std::path::Path::new(&input).join("broken.csv").exists());

    // Keys in use can't be deleted; delete the job first.
    let refused = app
        .follow(
            app.submit(&format!("/keys/{partner}/delete"), &session, "confirm=yes")
                .await,
            &session,
        )
        .await;
    assert!(refused.body.contains("outbound"), "{}", refused.body);
    app.submit(&format!("/jobs/{}/delete", job.id), &session, "confirm=yes")
        .await;
    assert!(app.vault().jobs().unwrap().is_empty());

    let actions = app.actions();
    for action in [
        "job.create",
        "job.update",
        "job.disable",
        "job.enable",
        "file.retry",
        "job.delete",
    ] {
        assert!(actions.contains(&action.to_owned()), "{action} audited");
    }
}

#[tokio::test]
async fn audit_log_filters_and_pages() {
    let app = App::new();
    let session = app.login().await;
    {
        let vault = app.vault();
        for i in 0..120 {
            vault
                .create_customer(Actor::Cli, &format!("C{i:03}"))
                .unwrap();
        }
    }
    let all = app.get("/audit", Some(&session)).await;
    assert_eq!(all.status, StatusCode::OK);
    assert!(all.body.contains("Older →"));
    assert!(all.body.contains("customer.create"));

    let logins = app.get("/audit?action=admin.", Some(&session)).await;
    assert!(logins.body.contains("admin.login"));
    assert!(!logins.body.contains("customer.create"));

    let href = all.body.split("href=\"/audit?").nth(1).unwrap();
    let older_query = &href[..href.find('"').unwrap()].replace("&amp;", "&");
    let older = app
        .get(&format!("/audit?{older_query}"), Some(&session))
        .await;
    assert!(older.body.contains("system.init"), "oldest page reached");
    assert!(older.body.contains("← Newest"));
}

#[tokio::test]
async fn admin_password_can_be_changed() {
    let app = App::new();
    let session = app.login().await;
    let other = app.login().await;

    let wrong = app
        .follow(
            app.submit(
                "/settings/password",
                &session,
                "current=wrong&new=another+long+password&repeat=another+long+password",
            )
            .await,
            &session,
        )
        .await;
    assert!(wrong.body.contains("current password is wrong"));

    let ok = app
        .follow(
            app.submit(
                "/settings/password",
                &session,
                &format!(
                    "current={}&new=another+long+password&repeat=another+long+password",
                    enc(PASSWORD)
                ),
            )
            .await,
            &session,
        )
        .await;
    assert!(ok.body.contains("Password changed"), "{}", ok.body);
    assert!(
        app.vault()
            .verify_admin_password("another long password")
            .unwrap()
    );
    assert_eq!(
        app.get("/", Some(&other)).await.status,
        StatusCode::SEE_OTHER,
        "other sessions ended"
    );
    assert_eq!(
        app.get("/", Some(&session)).await.status,
        StatusCode::OK,
        "this one kept"
    );
}

#[tokio::test]
async fn asset_urls_carry_a_hash_of_the_content() {
    // Browsers cache assets forever, so a changed file must get a new URL, even when the
    // version number doesn't change (a browser that saw an older build of the same version).
    let app = App::new();
    let login = app.get("/login", None).await.body;
    for asset in ["app.css", "app.js", "htmx.min.js"] {
        let prefix = format!("/static/{asset}?v=");
        let start = login
            .find(&prefix)
            .unwrap_or_else(|| panic!("{asset} linked"))
            + prefix.len();
        let linked = &login[start..start + 12];
        let served = app.get(&format!("/static/{asset}"), None).await;
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, served.body.as_bytes());
        let hash = hex::encode(sha2::Digest::finalize(hasher));
        assert_eq!(linked, &hash[..12], "{asset}");
    }
}

#[tokio::test]
async fn the_stylesheet_points_at_served_fonts() {
    let app = App::new();
    let css = app.get("/static/app.css", None).await.body;
    for font in ["geist-1.9.0.woff2", "jetbrains-mono-5.3.0.woff2"] {
        assert!(css.contains(&format!(r#"url("{font}")"#)), "{font}");
    }
    // All five layers are in it, tokens first.
    assert!(css.starts_with("/* Design tokens"));
    assert!(css.contains(".shell {") && css.contains(".btn {") && css.contains(".job-form"));
}

#[tokio::test]
async fn the_theme_choice_is_a_cookie_and_returns_to_the_page() {
    let app = App::new();
    let session = app.login().await;
    let page = app.get("/settings", Some(&session)).await;
    assert!(
        page.body.contains("<html lang=\"en\">"),
        "no theme until one is picked"
    );

    let request = Request::post("/theme")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::HOST, "localhost:8080")
        .header(header::ORIGIN, "http://localhost:8080")
        .header(header::REFERER, "http://localhost:8080/jobs?x=1")
        .header(header::COOKIE, &session.cookie);
    let reply = app
        .send(
            request
                .body(Body::from(format!("_csrf={}&theme=dark", session.csrf)))
                .unwrap(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location(), "/jobs?x=1");
    let cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with("watermelon_theme=dark;") && cookie.contains("SameSite=Strict"));

    let themed = Session {
        cookie: format!("{}; watermelon_theme=dark", session.cookie),
        csrf: session.csrf.clone(),
    };
    let page = app.get("/settings", Some(&themed)).await;
    assert!(page.body.contains(r#"<html lang="en" data-theme="dark">"#));
    assert!(page.body.contains(r#"value="dark" aria-pressed="true""#));
    let login = app
        .get(
            "/login",
            Some(&Session {
                cookie: "watermelon_theme=dark".into(),
                csrf: String::new(),
            }),
        )
        .await;
    assert!(login.body.contains(r#"data-theme="dark""#));

    // "system" forgets the choice; anything unknown counts as "system".
    let reply = app.submit("/theme", &session, "theme=system").await;
    assert_eq!(reply.location(), "/", "no Referer: back to the dashboard");
    assert!(
        reply.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let reply = app.submit("/theme", &session, "theme=%3Cscript%3E").await;
    assert!(
        reply.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );

    // Like every form, it needs the CSRF token.
    let reply = app.post("/theme", Some(&session), "theme=dark").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_style_guide_is_only_in_evaluation_builds() {
    let app = App::new();
    let session = app.login().await;
    let design = app.get("/design", Some(&session)).await;
    let dashboard = app.get("/", Some(&session)).await;
    if cfg!(feature = "evaluation") {
        assert_eq!(design.status, StatusCode::OK);
        assert!(dashboard.body.contains("Evaluation build"));
    } else {
        assert_eq!(design.status, StatusCode::NOT_FOUND);
        assert!(
            !dashboard.body.contains("Evaluation build") && !dashboard.body.contains("/design")
        );
    }
}

#[tokio::test]
async fn unknown_things_are_404() {
    let app = App::new();
    let session = app.login().await;
    for path in [
        "/nope",
        "/jobs/999",
        "/customers/999",
        "/keys/ABCDEF0123456789",
    ] {
        assert_eq!(
            app.get(path, Some(&session)).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}

#[tokio::test]
async fn audit_log_search_time_actor_chips_and_csv() {
    let app = App::new();
    let session = app.login().await;
    let acme = {
        let vault = app.vault();
        let acme = vault.create_customer(Actor::Cli, "ACME Corp").unwrap().id;
        vault
            .create_customer(Actor::Cli, "=cmd|' /C calc'!A0")
            .unwrap();
        vault
            .generate_key(
                Actor::Cli,
                acme,
                "Exports <exports@acme.example>",
                Algorithm::Curve25519,
            )
            .unwrap();
        acme
    };

    // Free text over subject (customer name, key user ID) and details.
    let found = app.get("/audit?q=exports%40acme", Some(&session)).await;
    assert!(found.body.contains("1 event"), "{}", found.body);
    assert!(found.body.contains("key.generate"));
    assert!(
        found
            .body
            .contains(r#"title="Remove this filter">“exports@acme”"#),
        "chip shown"
    );
    assert!(found.body.contains(r#"href="/audit">Clear all"#));
    let none = app.get("/audit?q=nothing+like+this", Some(&session)).await;
    assert!(none.body.contains("0 events") && none.body.contains("No events"));

    // Who did it.
    let web = app.get("/audit?actor=admin", Some(&session)).await;
    assert!(web.body.contains("admin.login") && !web.body.contains("customer.create"));
    assert!(web.body.contains(">Web UI (admin)<"));

    // Time: a period, a custom range, a bad date.
    let recent = app.get("/audit?period=1h", Some(&session)).await;
    assert!(recent.body.contains("customer.create"));
    let past = app
        .get("/audit?from=2001-01-01&to=2001-12-31", Some(&session))
        .await;
    assert!(past.body.contains("0 events"));
    assert!(past.body.contains(">2001-01-01 – 2001-12-31<"));
    let bad = app.get("/audit?from=yesterday", Some(&session)).await;
    assert_eq!(bad.status, StatusCode::OK);
    assert!(bad.body.contains("Ignored the from date"));

    // Combined, and a chip removes just its own filter.
    let both = app
        .get(
            &format!("/audit?customer={acme}&action=key."),
            Some(&session),
        )
        .await;
    assert!(both.body.contains("1 event"));
    assert!(
        both.body
            .contains(&format!(r#"href="/audit?customer={acme}""#)),
        "removing the action keeps the customer"
    );

    // CSV: what matches, oldest first, formula injection defused.
    let csv = app.get("/audit.csv?action=customer.", Some(&session)).await;
    assert_eq!(csv.status, StatusCode::OK);
    assert!(
        csv.headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/csv")
    );
    assert!(
        csv.headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains("watermelon-audit-")
    );
    let lines: Vec<&str> = csv.body.lines().collect();
    assert_eq!(lines[0], "id,time_utc,actor,action,customer,job,key,detail");
    assert_eq!(lines.len(), 3, "{}", csv.body);
    assert!(lines[1].contains("\"ACME Corp\""));
    assert!(lines[2].contains("\"'=cmd|' /C calc'!A0\""), "{}", lines[2]);
    assert_eq!(
        app.get("/audit.csv", None).await.status,
        StatusCode::SEE_OTHER,
        "needs login"
    );

    // Recent activity sections search the audit log, scoped to their page.
    let page = app.get(&format!("/customers/{acme}"), Some(&session)).await;
    assert!(page.body.contains(&format!(
        r#"<input type="hidden" name="customer" value="{acme}">"#
    )));
    assert!(page.body.contains("Search activity"));
}
