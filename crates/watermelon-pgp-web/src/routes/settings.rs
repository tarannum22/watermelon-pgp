use axum::{
    extract::State,
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
};
use maud::{Markup, html};
use serde::Deserialize;
use watermelon_pgp_core::{audit::Actor, vault::MIN_ADMIN_PASSWORD_LEN};
use zeroize::Zeroizing;

use crate::{
    AppState,
    auth::{self, Authed, Posted},
    error::AppError,
    ui::{self, Icon, Theme, Tone},
    views::{self, Nav},
};

pub async fn show(State(state): State<AppState>, auth: Authed) -> Markup {
    let page = state.page(&auth, "Settings", Nav::Settings);
    let min = MIN_ADMIN_PASSWORD_LEN.to_string();
    let hint = format!(
        "At least {MIN_ADMIN_PASSWORD_LEN} characters. Other open sessions are logged out."
    );
    views::layout(
        page,
        html! {
            (ui::page_header("Settings").subtitle(html! { "WatermelonPGP " (views::VERSION) }))
            div.grid-2 {
                (ui::panel(html! {
                    form.form method="post" action="/settings/password" {
                        (views::csrf_field(&auth.csrf))
                        (ui::field("Current password", None, html! { input type="password" name="current" required autocomplete="current-password"; }))
                        (ui::field("New password", Some(&hint), html! { input type="password" name="new" required minlength=(min) autocomplete="new-password"; }))
                        (ui::field("Repeat new password", None, html! { input type="password" name="repeat" required minlength=(min) autocomplete="new-password"; }))
                        div.actions { (ui::button("Change password").primary()) }
                    }
                }).title("Admin password").icon(Icon::Lock))
                div.stack {
                    (ui::panel(html! {
                        p { "Follow the system setting, or pick one. Remembered in this browser." }
                        (ui::theme_switch(views::csrf_field(&auth.csrf), auth.theme))
                    }).title("Appearance").icon(Icon::Sun))
                    (ui::panel(html! {
                        p { "Take a consistent snapshot of the database on the server:" }
                        (ui::terminal(html! { "watermelon backup /backups/watermelon-$(date +%F).db" }))
                        (ui::alert(Tone::Warn, None, html! {
                            "The master key is not part of the backup. Keep a copy of it somewhere else, "
                            "or the secret keys in the backup are unrecoverable."
                        }))
                    }).title("Backups").icon(Icon::Download))
                }
            }
        },
    )
}

#[derive(Deserialize)]
pub struct ThemeForm {
    theme: String,
}

/// Remember the chosen theme, then go back to the page the switch was on.
pub async fn set_theme(
    State(state): State<AppState>,
    headers: HeaderMap,
    posted: Posted<ThemeForm>,
) -> Response {
    let theme = Theme::from_value(&posted.form.theme);
    let back = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
        .and_then(local_path)
        .unwrap_or("/")
        .to_owned();
    (
        [(
            header::SET_COOKIE,
            auth::theme_cookie(theme, state.config().secure_cookies),
        )],
        Redirect::to(&back),
    )
        .into_response()
}

/// The path and query of a URL, if it is safe to redirect to (same site, not `//host`).
fn local_path(url: &str) -> Option<&str> {
    let path = match url.split_once("://") {
        Some((_, rest)) => &rest[rest.find('/')?..],
        None => url,
    };
    (path.starts_with('/') && !path.starts_with("//") && !path.contains('\\')).then_some(path)
}

#[derive(Deserialize)]
pub struct PasswordForm {
    current: String,
    new: String,
    repeat: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    posted: Posted<PasswordForm>,
) -> Redirect {
    let auth = posted.auth;
    let current = Zeroizing::new(posted.form.current);
    let new = Zeroizing::new(posted.form.new);
    let repeat = Zeroizing::new(posted.form.repeat);
    let outcome = async {
        // Checking the current password is a login attempt as far as guessing goes.
        if let Err(wait) = state.limiter().check(&auth.client) {
            return Err(AppError::bad_request(format!(
                "too many failed attempts; try again in {} seconds",
                wait.as_secs() + 1
            )));
        }
        if *new != *repeat {
            return Err(AppError::bad_request("the two new passwords do not match"));
        }
        let client = auth.client.clone();
        let changed = state
            .vault(move |vault| {
                if !vault.login(&current, &client)? {
                    return Ok(false);
                }
                vault.set_admin_password(Actor::Admin, &new)?;
                Ok(true)
            })
            .await?;
        if !changed {
            state.limiter().failed(&auth.client);
            return Err(AppError::bad_request("the current password is wrong"));
        }
        state.sessions().remove_others(auth.key);
        Ok("Password changed. Other sessions were logged out.".to_owned())
    }
    .await;
    state.done(&auth, "/settings", outcome)
}

#[cfg(test)]
mod tests {
    use super::local_path;

    #[test]
    fn only_local_paths_are_redirect_targets() {
        assert_eq!(
            local_path("http://localhost:8080/jobs/3?x=1"),
            Some("/jobs/3?x=1")
        );
        assert_eq!(local_path("https://example.com"), None);
        assert_eq!(local_path("https://example.com//evil.com/"), None);
        assert_eq!(local_path("/audit"), Some("/audit"));
        assert_eq!(local_path("/\\evil.com"), None);
    }
}
