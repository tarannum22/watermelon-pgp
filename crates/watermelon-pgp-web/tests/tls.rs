//! Serving HTTPS on a real socket with a self-signed certificate.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};
use watermelon_pgp_core::{
    envelope::MasterKey,
    vault::{self, Vault},
};
use watermelon_pgp_web::{AppState, Config, Tls, serve};

#[tokio::test(flavor = "multi_thread")]
async fn serves_https_with_hsts() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join(vault::MASTER_KEY_FILE);
    let report = Vault::init(&dir.path().join("data"), &key_path, "a long admin password").unwrap();
    let vault = Vault::open(&report.db_path, MasterKey::load(&key_path).unwrap()).unwrap();
    let state = AppState::new(
        Arc::new(Mutex::new(vault)),
        Config {
            secure_cookies: true,
            hsts: true,
        },
    );

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert_path, certified.cert.pem()).unwrap();
    std::fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();
    let tls = Tls::load(&cert_path, &key_path).await.unwrap();
    tls.reload(&cert_path, &key_path).await.unwrap();
    assert!(
        Tls::load(&key_path, &cert_path).await.is_err(),
        "swapped files are rejected"
    );

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(state, listener, Some(tls), async {
        let _ = stopped.await;
    }));

    let mut roots = RootCertStore::empty();
    roots.add(certified.cert.der().clone()).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut stream = TlsConnector::from(Arc::new(client))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let lower = response.to_ascii_lowercase();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(lower.contains("strict-transport-security: max-age=31536000"));
    assert!(response.ends_with(r#"{"status":"ok"}"#));

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
