use axum::{
    Form,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use maud::{Markup, Render, html};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::Empty;
use crate::{
    AppState,
    auth::{self, Authed, Client, Posted, ThemeChoice},
    ui::{self, Theme, Tone, icons},
    views,
};

fn login_page(theme: Theme, error: Option<&str>) -> Markup {
    views::bare(
        "Log in",
        theme,
        ui::panel(html! {
            form.form method="post" action="/login" {
                div {
                    h1 { "Log in" }
                    p.muted { "Manage keys and file encryption jobs." }
                }
                @if let Some(error) = error {
                    (ui::alert(Tone::Bad, None, html! { (error) }))
                }
                (ui::field("Admin password", None, html! {
                    input type="password" name="password" autocomplete="current-password" required autofocus;
                }))
                (ui::button("Log in").primary().block().icon(icons::LOCK))
            }
        })
        .render(),
    )
}

pub async fn login_form(
    ThemeChoice(theme): ThemeChoice,
    auth: Result<Authed, Response>,
) -> Response {
    match auth {
        Ok(_) => Redirect::to("/").into_response(),
        Err(_) => login_page(theme, None).into_response(),
    }
}

#[derive(Deserialize)]
pub struct LoginForm {
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    Client(client): Client,
    ThemeChoice(theme): ThemeChoice,
    Form(form): Form<LoginForm>,
) -> Response {
    let password = Zeroizing::new(form.password);
    if let Err(wait) = state.limiter().check(&client) {
        let message = format!(
            "Too many failed attempts. Try again in {} seconds.",
            wait.as_secs() + 1
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            login_page(theme, Some(&message)),
        )
            .into_response();
    }
    let checked = {
        let client = client.clone();
        state
            .vault(move |vault| vault.login(&password, &client))
            .await
    };
    match checked {
        Ok(true) => {
            state.limiter().succeeded(&client);
            let token = state.sessions().create();
            (
                [(
                    header::SET_COOKIE,
                    auth::session_cookie(&token, state.config().secure_cookies),
                )],
                Redirect::to("/"),
            )
                .into_response()
        }
        Ok(false) => {
            state.limiter().failed(&client);
            (
                StatusCode::UNAUTHORIZED,
                login_page(theme, Some("Wrong password.")),
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

pub async fn logout(State(state): State<AppState>, posted: Posted<Empty>) -> Response {
    let auth = posted.auth;
    let client = auth.client.clone();
    // Logging out must work even if auditing it fails.
    if let Err(e) = state.vault(move |vault| vault.record_logout(&client)).await {
        tracing::error!(error = e.message(), "auditing logout failed");
    }
    state.sessions().remove(auth.key);
    (
        [(
            header::SET_COOKIE,
            auth::clear_cookie(state.config().secure_cookies),
        )],
        Redirect::to("/login"),
    )
        .into_response()
}
