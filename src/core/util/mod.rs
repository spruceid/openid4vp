use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use http::{Request, Response};
use url::{Host, Url};

/// Check that a Verifier endpoint (`request_uri`, `response_uri`) uses TLS.
///
/// The rule:
/// - a URL with the `https` scheme is accepted;
/// - a URL with the `http` scheme is accepted only in debug builds (`cfg(debug_assertions)`)
///   and only when its host is loopback: the domain `localhost` (case-insensitive), an IPv4
///   address in `127.0.0.0/8`, or the IPv6 address `::1`. This keeps local tests and
///   examples working;
/// - every other URL is refused.
///
/// OID4VP 1.0 sends the Authorization Response "via an HTTPS connection" (Section 5.2,
/// `response_mode`), requires the `https` scheme for the Request URI (Section 5.10: "The
/// request MUST use the HTTP POST method with the `https` scheme"), and requires
/// implementations to follow BCP195 (Section 14.6, "TLS Requirements"). Without TLS, an
/// attacker on the network can read or change the Request Object and the `vp_token`.
///
/// `parameter` is the name of the checked value (for example `"response_uri"`); the error
/// message contains it.
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
#[async_trait]
pub trait AsyncHttpClient {
    async fn execute(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>>;
}

pub(crate) fn base_request() -> http::request::Builder {
    Request::builder().header("Prefer", "OID4VP-1.0.0")
}

#[derive(Debug, Clone)]
pub struct ReqwestClient(reqwest::Client);

impl AsRef<reqwest::Client> for ReqwestClient {
    fn as_ref(&self) -> &reqwest::Client {
        &self.0
    }
}

impl ReqwestClient {
    pub fn new() -> Result<Self> {
        reqwest::Client::builder()
            .use_rustls_tls()
            // Refuse plain http in release builds. reqwest's `https_only` has no loopback
            // exception, and tests and examples talk to local servers over http, so debug
            // builds rely on `require_https` alone.
            .https_only(!cfg!(debug_assertions))
            // Apply `require_https` to every redirect target too. Without this, debug builds
            // (where `https_only` is off) follow a redirect from an accepted endpoint to any
            // http host, and a 307/308 on the response POST resends the `vp_token` in clear
            // text.
            .redirect(https_redirect_policy())
            .build()
            .context("unable to build http_client")
            .map(Self)
    }
}

/// Maximum number of redirects that [ReqwestClient] follows (reqwest's default).
const MAX_REDIRECTS: usize = 10;

/// Redirect policy that follows a redirect only when its target passes [require_https].
fn https_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        match require_https(attempt.url(), "redirect target") {
            Ok(()) => attempt.follow(),
            Err(error) => attempt.error(error),
        }
    })
}

#[async_trait]
impl AsyncHttpClient for ReqwestClient {
    async fn execute(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>> {
        let response = self
            .0
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
    use axum::{
        http::{header, StatusCode},
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
                .route("/ok", any(|| async { "ok" }));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    #[tokio::test]
    async fn refuses_a_redirect_to_a_public_http_host() {
        let base = redirect_server().await;
        let request = http::Request::post(format!("{base}/to-public"))
            .body(b"vp_token=secret".to_vec())
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
