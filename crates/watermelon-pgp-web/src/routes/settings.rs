use axum::{extract::State, response::Redirect};
use maud::{Markup, html};
use serde::Deserialize;
use watermelon_pgp_core::{audit::Actor, vault::MIN_ADMIN_PASSWORD_LEN};
use zeroize::Zeroizing;

use crate::{
    AppState,
    auth::{Authed, Posted},
    error::AppError,
    views::{self, Nav},
};

pub async fn show(State(state): State<AppState>, auth: Authed) -> Markup {
    let page = state.page(&auth, "Settings", Nav::Settings);
    views::layout(
        page,
        html! {
            h1 { "Settings" }
            section.card {
                h2 { "Admin password" }
                form.stack method="post" action="/settings/password" {
                    (views::csrf_field(&auth.csrf))
                    label { "Current password" input type="password" name="current" required autocomplete="current-password"; }
                    label { "New password" input type="password" name="new" required minlength=(MIN_ADMIN_PASSWORD_LEN) autocomplete="new-password"; }
                    label { "Repeat new password" input type="password" name="repeat" required minlength=(MIN_ADMIN_PASSWORD_LEN) autocomplete="new-password"; }
                    p.hint { "At least " (MIN_ADMIN_PASSWORD_LEN) " characters. Other open sessions are logged out." }
                    button.primary type="submit" { "Change password" }
                }
            }
            section.card {
                h2 { "Backups" }
                p {
                    "Run " code { "watermelon backup <file>" } " on the server for a consistent snapshot of the database. "
                    "The master key is not part of it: keep a copy of it somewhere else, or the secret keys in the backup are unrecoverable."
                }
            }
            p.muted { "watermelon-pgp " (views::VERSION) }
        },
    )
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
