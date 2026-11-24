use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use http::{Request, Response};
use url::{Host, Url};

/// Check that a Verifier endpoint (`request_uri`, `response_uri`) uses TLS, as OID4VP 1.0
/// requires through BCP195 (Section 14.6, "TLS Requirements").
///
/// - `https` is accepted.
/// - `http` is accepted only when this crate is built with `debug_assertions`, and only for a
///   loopback host: `localhost`, `127.0.0.0/8` or `::1`. `debug_assertions` follows the build
///   profile of the application that links this crate, so a Wallet's debug build accepts
///   loopback http and its release build does not.
/// - Every other URL is refused.
///
/// `parameter` names the checked value in the error, for example `"response_uri"`.
pub fn require_https(url: &Url, parameter: &str) -> Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if cfg!(debug_assertions) && is_loopback(url) => Ok(()),
        _ => bail!("'{parameter}' must use the https scheme, found '{url}'"),
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Generic HTTP client.
///
/// A trait is used here so to facilitate native HTTP/TLS when compiled for mobile applications.
///
/// The crate checks only the first URL of each request. Implementations must not follow a
/// redirect whose target fails [require_https], and should follow redirects only for GET and
/// HEAD. The Authorization Response is a POST: a 307 or 308 would resend the `vp_token` to a
/// host that was never checked against the `client_id`, and OID4VP 1.0 (Section 8.2) has the
/// Response URI answer with 200.
#[async_trait]
pub trait AsyncHttpClient {
    async fn execute(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>>;
}

pub(crate) fn base_request() -> http::request::Builder {
    Request::builder().header("Prefer", "OID4VP-1.0.0")
}

/// [AsyncHttpClient] on reqwest.
///
/// GET and HEAD requests follow redirects whose targets pass [require_https]. Other requests
/// follow no redirect and return the 3xx response as it is.
#[derive(Debug, Clone)]
pub struct ReqwestClient {
    client: reqwest::Client,
    without_redirects: reqwest::Client,
}

/// The client used for GET and HEAD, which follows redirects. A POST sent through it directly
/// follows redirects too; [AsyncHttpClient::execute] is the path that refuses them.
impl AsRef<reqwest::Client> for ReqwestClient {
    fn as_ref(&self) -> &reqwest::Client {
        &self.client
    }
}

impl ReqwestClient {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: builder()
                .redirect(https_redirect_policy())
                .build()
                .context("unable to build http_client")?,
            without_redirects: builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("unable to build http_client")?,
        })
    }
}

fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .use_rustls_tls()
        // No loopback exception in `https_only`, so debug builds rely on `require_https`.
        .https_only(!cfg!(debug_assertions))
}

/// Every redirect target must pass [require_https], then reqwest's default limit of 10 hops
/// applies. The check matters in debug builds, where `https_only` is off.
fn https_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        match require_https(attempt.url(), "redirect target") {
            Ok(()) => reqwest::redirect::Policy::default().redirect(attempt),
            Err(error) => attempt.error(error),
        }
    })
}

#[async_trait]
impl AsyncHttpClient for ReqwestClient {
    async fn execute(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>> {
        let client = match *request.method() {
            http::Method::GET | http::Method::HEAD => &self.client,
            _ => &self.without_redirects,
        };
        let response = client
            .execute(request.try_into().context("unable to convert request")?)
            .await
            .context("http request failed")?;

        let mut builder = Response::builder()
            .status(response.status())
            .version(response.version());

        builder
            .extensions_mut()
            .context("unable to set extensions")?
            .extend(response.extensions().clone());

        builder
            .headers_mut()
            .context("unable to set headers")?
            .extend(response.headers().clone());

        builder
            .body(
                response
                    .bytes()
                    .await
                    .context("failed to extract response body")?
                    .to_vec(),
            )
            .context("unable to construct response")
    }
}

#[cfg(test)]
mod test {
    use http::Response;
    use url::Url;

    use super::require_https;
    #[cfg(not(debug_assertions))]
    use super::{AsyncHttpClient, ReqwestClient};

    const LOOPBACK_HTTP: [&str; 6] = [
        "http://127.0.0.1:3000/cb",
        "http://127.1.2.3/cb",
        "http://[::1]/cb",
        "http://[::1]:8080/cb",
        "http://localhost/cb",
        "http://LocalHost:3000/cb",
    ];

    fn check(url: &str, parameter: &str) -> anyhow::Result<()> {
        require_https(&url.parse::<Url>().unwrap(), parameter)
    }

    #[test]
    fn debug() {
        Response::builder().extensions_mut().unwrap();
        Response::builder().headers_mut().unwrap();
    }

    #[test]
    fn require_https_accepts_https() {
        check("https://verifier.example/cb", "response_uri").unwrap();
        check("https://127.0.0.1/request/1", "request_uri").unwrap();
        check("HTTPS://verifier.example:8443/cb", "response_uri").unwrap();
    }

    #[test]
    fn require_https_refuses_http_on_remote_host() {
        for parameter in ["request_uri", "response_uri"] {
            let err = check("http://evil.example/cb", parameter).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(parameter), "{msg}");
            assert!(msg.contains("http://evil.example/cb"), "{msg}");
            assert!(msg.contains("https"), "{msg}");
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn require_https_accepts_http_on_loopback_in_debug() {
        for url in LOOPBACK_HTTP {
            check(url, "response_uri").unwrap_or_else(|e| panic!("{url}: {e}"));
        }
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn require_https_refuses_http_on_loopback_in_release() {
        for url in LOOPBACK_HTTP {
            assert!(check(url, "response_uri").is_err(), "{url}");
        }
    }

    #[tokio::test]
    #[cfg(not(debug_assertions))]
    async fn reqwest_client_refuses_loopback_http_in_release() {
        let client = ReqwestClient::new().unwrap();
        for method in [http::Method::GET, http::Method::POST] {
            let request = http::Request::builder()
                .method(method.clone())
                .uri("http://127.0.0.1:9/")
                .body(vec![])
                .unwrap();
            let err = client.execute(request).await.unwrap_err();
            assert!(
                format!("{err:#}").contains("URL scheme is not allowed"),
                "{method}: {err:#}"
            );
        }
    }

    #[test]
    fn require_https_refuses_http_on_non_loopback_host() {
        for url in [
            "http://192.168.1.10/cb",
            "http://10.0.2.2:3000/cb",
            "http://localhost.evil.example/cb",
            "http://127.0.0.1.evil.example/cb",
            "http://[::2]/cb",
            "http://0.0.0.0/cb",
        ] {
            assert!(check(url, "response_uri").is_err(), "{url}");
        }
    }

    #[test]
    fn require_https_refuses_other_schemes() {
        for url in [
            "ftp://verifier.example/cb",
            "file:///etc/passwd",
            "file://localhost/etc/passwd",
            "openid4vp://authorize?request_uri=x",
            "data:text/plain,hello",
            "ws://localhost/cb",
        ] {
            assert!(check(url, "request_uri").is_err(), "{url}");
        }
    }
}

/// Redirects are checked with [require_https] too. Debug builds only: they need a plain-http
/// loopback server, and release builds refuse http before any redirect.
#[cfg(all(test, debug_assertions))]
mod redirect_test {
    use std::collections::HashMap;

    use axum::{
        extract::{Path, Query},
        http::{header, StatusCode},
        response::IntoResponse,
        routing::any,
        Router,
    };

    use super::{AsyncHttpClient, ReqwestClient};

    /// Start a loopback server: `/to-public` redirects (307) to a public http host,
    /// `/to-loopback` redirects to `/ok` on the same server, `/ok` answers 200.
    async fn redirect_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let ok = format!("{base}/ok");
        let app =
            Router::new()
                .route(
                    "/to-public",
                    any(|| async {
                        (
                            StatusCode::TEMPORARY_REDIRECT,
                            [(header::LOCATION, "http://evil.example/cb")],
                        )
                    }),
                )
                .route(
                    "/to-loopback",
                    any(move || async move {
                        (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, ok)])
                    }),
                )
                .route("/ok", any(|| async { "ok" }))
                .route(
                    "/chain/:n",
                    any(|Path(n): Path<u32>| async move {
                        match n {
                            0 => "ok".into_response(),
                            n => (
                                StatusCode::TEMPORARY_REDIRECT,
                                [(header::LOCATION, format!("/chain/{}", n - 1))],
                            )
                                .into_response(),
                        }
                    }),
                )
                .route(
                    "/to-other-origin",
                    any(|Query(q): Query<HashMap<String, String>>| async move {
                        let status = q
                            .get("status")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(StatusCode::TEMPORARY_REDIRECT);
                        (status, [(header::LOCATION, q["to"].clone())])
                    }),
                );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    async fn send(method: http::Method, url: String) -> anyhow::Result<http::Response<Vec<u8>>> {
        let request = http::Request::builder()
            .method(method)
            .uri(url)
            .body(b"vp_token=secret".to_vec())
            .unwrap();
        ReqwestClient::new().unwrap().execute(request).await
    }

    #[tokio::test]
    async fn follows_ten_redirects() {
        let base = redirect_server().await;
        let response = send(http::Method::GET, format!("{base}/chain/10"))
            .await
            .unwrap();
        assert_eq!(response.body(), b"ok");
    }

    /// `localhost` and `127.0.0.1` are different origins, though the same server answers.
    fn other_origin(base: &str, status: u16) -> String {
        let to = base.replace("127.0.0.1", "localhost") + "/ok";
        format!("{base}/to-other-origin?status={status}&to={to}")
    }

    #[tokio::test]
    async fn a_post_follows_no_redirect() {
        let base = redirect_server().await;
        for status in [301, 302, 303, 307, 308] {
            let response = send(http::Method::POST, other_origin(&base, status))
                .await
                .unwrap();
            assert_eq!(response.status(), status);
        }
        let response = send(http::Method::POST, format!("{base}/to-loopback"))
            .await
            .unwrap();
        assert_eq!(response.status(), 307);
    }

    #[tokio::test]
    async fn a_get_follows_a_redirect_to_another_origin() {
        let base = redirect_server().await;
        let response = send(http::Method::GET, other_origin(&base, 307))
            .await
            .unwrap();
        assert_eq!(response.body(), b"ok");
    }

    #[tokio::test]
    async fn refuses_an_eleventh_redirect() {
        let base = redirect_server().await;
        let err = send(http::Method::GET, format!("{base}/chain/11"))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("too many redirects"), "{err:#}");
    }

    #[tokio::test]
    async fn refuses_a_redirect_to_a_public_http_host() {
        let base = redirect_server().await;
        let request = http::Request::get(format!("{base}/to-public"))
            .body(vec![])
            .unwrap();
        let err = ReqwestClient::new()
            .unwrap()
            .execute(request)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("'redirect target' must use the https scheme"),
            "{msg}"
        );
        assert!(msg.contains("http://evil.example/cb"), "{msg}");
    }

    #[tokio::test]
    async fn follows_a_redirect_to_loopback() {
        let base = redirect_server().await;
        let request = http::Request::get(format!("{base}/to-loopback"))
            .body(vec![])
            .unwrap();
        let response = ReqwestClient::new()
            .unwrap()
            .execute(request)
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"ok");
    }
}
