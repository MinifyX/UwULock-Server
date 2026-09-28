//! Backups into an S3 bucket, against a small stand-in for S3 that runs inside the test: it keeps
//! objects in memory, pages its listings, checks every signature the way S3 does, and is busy once.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use uwulock_backup::s3::{Credentials, authorization};
use uwulock_backup::{Error, RepoKey, Repository, S3Target, Storage, Target};

use crate::support::*;

const ACCESS_KEY: &str = "AKIDEXAMPLE";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const BUCKET: &str = "uwulock-backups";
/// Small pages, so listings have to follow continuation tokens.
const PAGE: usize = 3;

#[derive(Default)]
struct Bucket {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    requests: AtomicUsize,
    /// Answers 503 to this many PUTs first, like S3 asking to slow down.
    busy: AtomicUsize,
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, format!("<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>{code}</Message></Error>"))
        .into_response()
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes).as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn handle(bucket: Arc<Bucket>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    bucket.requests.fetch_add(1, Ordering::SeqCst);
    let path = uri.path().to_owned();
    let query = uri.query().unwrap_or_default().to_owned();
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
    let (host, date, payload, given) =
        (header("host"), header("x-amz-date"), header("x-amz-content-sha256"), header("authorization"));

    // What S3 checks: the payload is the one signed for, and the signature is right.
    if sha256_hex(&body) != payload {
        return error(StatusCode::BAD_REQUEST, "XAmzContentSHA256Mismatch");
    }
    let credentials = Credentials { access_key: ACCESS_KEY, secret_key: SECRET_KEY, region: "eu-central-1" };
    let signed = [("host", host.as_str()), ("x-amz-content-sha256", payload.as_str()), ("x-amz-date", date.as_str())];
    if date.len() != 16
        || authorization(&credentials, method.as_str(), &path, &query, &signed, &payload, &date) != given
    {
        return error(StatusCode::FORBIDDEN, "SignatureDoesNotMatch");
    }

    let Some(rest) = path.strip_prefix(&format!("/{BUCKET}")) else {
        return error(StatusCode::NOT_FOUND, "NoSuchBucket");
    };
    let key = decode(rest.trim_start_matches('/'));
    let mut objects = bucket.objects.lock().unwrap();
    match (method.as_str(), key.is_empty()) {
        ("PUT", false) => {
            if bucket.busy.load(Ordering::SeqCst) > 0 {
                bucket.busy.fetch_sub(1, Ordering::SeqCst);
                return error(StatusCode::SERVICE_UNAVAILABLE, "SlowDown");
            }
            objects.insert(key, body.to_vec());
            StatusCode::OK.into_response()
        }
        ("GET", false) => match objects.get(&key) {
            Some(content) => (StatusCode::OK, content.clone()).into_response(),
            None => error(StatusCode::NOT_FOUND, "NoSuchKey"),
        },
        ("DELETE", false) => {
            objects.remove(&key);
            StatusCode::NO_CONTENT.into_response()
        }
        ("GET", true) => {
            let params: BTreeMap<String, String> = query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .map(|(name, value)| (decode(name), decode(value)))
                .collect();
            assert_eq!(params.get("list-type").map(String::as_str), Some("2"));
            assert_eq!(params.get("delimiter").map(String::as_str), Some("/"));
            let prefix = params.get("prefix").cloned().unwrap_or_default();
            let after = params.get("continuation-token").cloned().unwrap_or_default();
            // Every name directly under the prefix: objects, and the folders below it.
            let mut entries: Vec<(String, bool)> = Vec::new();
            for name in objects.keys().filter_map(|key| key.strip_prefix(&prefix)) {
                match name.split_once('/') {
                    Some((folder, _)) => {
                        let common = format!("{prefix}{folder}/");
                        if !entries.contains(&(common.clone(), true)) {
                            entries.push((common, true));
                        }
                    }
                    None => entries.push((format!("{prefix}{name}"), false)),
                }
            }
            entries.sort();
            entries.retain(|(name, _)| name.as_str() > after.as_str());
            let truncated = entries.len() > PAGE;
            entries.truncate(PAGE);
            let mut xml = format!("<ListBucketResult><Name>{BUCKET}</Name><IsTruncated>{truncated}</IsTruncated>");
            for (name, common) in &entries {
                if *common {
                    xml.push_str(&format!("<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>", escape(name)));
                } else {
                    xml.push_str(&format!("<Contents><Key>{}</Key><Size>1</Size></Contents>", escape(name)));
                }
            }
            if truncated {
                let last = &entries.last().unwrap().0;
                xml.push_str(&format!("<NextContinuationToken>{}</NextContinuationToken>", escape(last)));
            }
            xml.push_str("</ListBucketResult>");
            (StatusCode::OK, xml).into_response()
        }
        _ => error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed"),
    }
}

async fn fake_s3() -> (SocketAddr, Arc<Bucket>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let bucket = Arc::new(Bucket::default());
    let serving = bucket.clone();
    let app = axum::Router::new().fallback(move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
        handle(serving.clone(), method, uri, headers, body)
    });
    tokio::spawn(async move { axum::serve(listener, app).await });
    (address, bucket)
}

fn target(address: SocketAddr, secret_key: &str) -> Target {
    Target::S3(S3Target {
        endpoint: format!("http://{address}"),
        region: "eu-central-1".into(),
        bucket: BUCKET.into(),
        prefix: "server one/uwulock".into(),
        access_key: ACCESS_KEY.into(),
        secret_key: secret_key.into(),
        path_style: true,
    })
}

#[tokio::test]
async fn a_backup_goes_into_a_bucket_and_comes_back() {
    let (address, bucket) = fake_s3().await;
    let server = Server::new().await;
    let key = RepoKey::generate();
    bucket.busy.store(1, Ordering::SeqCst);
    let storage = Storage::open(&target(address, SECRET_KEY)).await.unwrap();
    storage.check_writable().await.unwrap();
    let repo = Repository::open(storage, Some(key.clone()), 1).await.unwrap();
    let report = server.backup(&repo, 1_000).await;
    assert_eq!(bucket.busy.load(Ordering::SeqCst), 0, "asked again after SlowDown");
    assert!(uwulock_backup::check(&repo, &report.snapshot).await.unwrap().is_empty());
    {
        let objects = bucket.objects.lock().unwrap();
        assert!(objects.keys().all(|key| key.starts_with("server one/uwulock/")), "{:?}", objects.keys());
        assert!(objects.len() > PAGE * 2, "listings had to be paged");
        assert!(!objects.contains_key("server one/uwulock/uwulock-write-test"));
    }

    let new = tempfile::tempdir().unwrap();
    let storage = Storage::open(&target(address, SECRET_KEY)).await.unwrap();
    let repo = Repository::open_existing(storage, Some(key)).await.unwrap();
    assert_eq!(repo.listing().await.unwrap().len(), 1);
    uwulock_backup::restore_into(&repo, &report.snapshot, new.path()).await.unwrap();
    check_restored(new.path()).await;

    let wrong = Storage::open(&target(address, "not the secret")).await.unwrap();
    assert!(matches!(wrong.list("snapshots").await, Err(Error::LoginRefused(_))));
}
