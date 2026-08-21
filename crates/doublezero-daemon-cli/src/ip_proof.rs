//! RFC-27 IP ownership proof retrieval for `connect`.
//!
//! `client_ip` is a plain argument to user creation: nothing onchain attests that the caller can
//! originate traffic from it. RFC-27 closes that with a proof signed by a DoubleZero-operated
//! verifier, and this is where `connect` obtains one.
//!
//! **The service, not the host, decides the address.** The verifier signs the source address it
//! observes the request originate from and refuses to accept a caller-supplied one — the request
//! body has no `client_ip` field at all. So the proof it returns is the authoritative value, and
//! the daemon's own discovery (`resolve_client_ip`, ultimately `ifconfig.me` inside
//! `doublezerod`) is a convenience for display and pre-flight checks. Where the two disagree,
//! `connect` stops rather than guessing.
//!
//! Retrieval is deliberately best-effort. A host with no reachable verifier, or behind CGNAT,
//! still connects: creation proceeds without a proof and the program decides, which succeeds
//! while `require-ip-ownership-proof` is clear and fails cleanly once it is set. The one hard
//! failure is a proof for an address that is not the one being provisioned, because attaching it
//! would guarantee an onchain rejection and ignoring it would bind an address nobody proved.

use std::{net::Ipv4Addr, str::FromStr, thread, time::Duration};

use doublezero_ip_proof::IpOwnershipProof;
use doublezero_sdk::UserType;
use mockall::automock;
use serde::Deserialize;
use solana_sdk::{pubkey::Pubkey, signature::Signature};
use tracing::debug;

/// How long to wait on one attempt before giving up and letting the program decide. Short on
/// purpose: `connect` is interactive, and the fallback is a working connection while the feature
/// flag is clear. [`MAX_ATTEMPTS`] of these plus the delay between them is the whole budget.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(2500);

/// Abandon one address this fast so a second DNS answer is actually reached. hyper tries the
/// resolved addresses in sequence, but its happy-eyeballs timer only crosses address families,
/// not two A records — so without a connect timeout a blackholed address (SYN dropped, which is
/// how a host that is down or firewalled usually fails) burns the entire request budget and its
/// siblings are never tried. Redundant A records are then a coin flip rather than redundancy.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Attempts before giving up. `POST /v1/proof` is idempotent — it signs the address it observes
/// and holds no per-request state — so a retry cannot double anything, and a second attempt may
/// resolve to a healthy host behind the same name. Only a transport error or a 5xx is retried:
/// a decline (`rate_limited` above all) and a malformed body are answers that will not change.
const MAX_ATTEMPTS: u32 = 2;

/// Between attempts. Short, for the same reason the timeout is.
const RETRY_DELAY: Duration = Duration::from_millis(250);

/// Why no proof is available. Every variant is a reason to *continue* without one — the program
/// is the enforcement point, and refusing to connect here would break every host in an
/// environment whose flag is still clear. They are separated so the operator learns which one
/// happened, because the remedies are completely different.
#[derive(Debug, thiserror::Error)]
pub enum IpProofError {
    /// No verifier is deployed for this environment and none was configured (#4199).
    #[error("no IP ownership verification service is configured for this environment")]
    NotConfigured,

    /// The service could not be reached: DNS, connect, TLS, or timeout.
    #[error("could not reach the IP ownership verification service at {url}: {detail}")]
    Unreachable { url: String, detail: String },

    /// The service answered and declined. `reason` is its stable machine-readable code — notably
    /// `not_globally_routable` for a CGNAT or RFC-1918 source, and `rate_limited`.
    #[error(
        "the IP ownership verification service declined to issue a proof ({reason}): {message}"
    )]
    Declined { reason: String, message: String },

    /// The service answered with something this client cannot turn into a proof. A version skew
    /// or a captive portal in the path both land here.
    #[error("could not read the proof the verification service returned: {0}")]
    Malformed(String),
}

/// Obtains an RFC-27 proof for the calling host.
#[automock]
pub trait IpProofClient: Send + Sync {
    /// Request a proof binding `payer`, the address the service observes, and `user_type`.
    ///
    /// `source_addr` is the address the tunnel will use; the implementation binds the outbound
    /// request to it where it can, so a multi-homed host proves the address it will actually
    /// originate tunnel traffic from rather than whichever one the routing table prefers.
    fn request_proof(
        &self,
        payer: Pubkey,
        user_type: UserType,
        source_addr: Ipv4Addr,
    ) -> Result<IpOwnershipProof, IpProofError>;
}

/// Mirrors the service's `ProofResponse`. Deliberately a separate type from `IpOwnershipProof`:
/// the wire form carries base58 strings, and a field the program does not understand must fail
/// here rather than be silently coerced.
#[derive(Debug, Deserialize)]
struct ProofResponse {
    version: u8,
    payer: String,
    client_ip: Ipv4Addr,
    epoch: u64,
    user_type: u8,
    signature: String,
}

/// Mirrors the service's `ErrorResponse`.
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

/// The real client. `None` for `base_url` models an environment with no verifier, so the caller
/// does not have to special-case its own configuration.
pub struct HttpIpProofClient {
    base_url: Option<String>,
}

impl HttpIpProofClient {
    pub fn new(base_url: Option<String>) -> Self {
        Self { base_url }
    }

    /// Blocking on purpose: it sits alongside `LedgerClient`'s blocking RPC calls in the same
    /// `connect` code path, and one short request per invocation does not justify a second
    /// async HTTP stack in this crate.
    fn build(
        source_addr: Ipv4Addr,
        url: &str,
    ) -> Result<(reqwest::blocking::Client, bool), IpProofError> {
        // Bind the request to the address the tunnel will use, so a multi-homed host proves the
        // right one. On a NATed host that address is not assigned to any local interface and the
        // bind fails, which is expected, not an error: fall back to an unbound request, where
        // the service observes the NAT's public address — the same address the daemon
        // discovered. Both paths are reported, because a silent fallback on a multi-homed host
        // would prove the wrong address.
        match reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .local_address(Some(std::net::IpAddr::V4(source_addr)))
            .build()
        {
            Ok(client) => Ok((client, true)),
            Err(bind_err) => {
                debug!(
                    %source_addr,
                    error = %bind_err,
                    "could not bind the verification request to the tunnel source address; \
                     falling back to the host's default egress"
                );
                let client = reqwest::blocking::Client::builder()
                    .timeout(REQUEST_TIMEOUT)
                    .connect_timeout(CONNECT_TIMEOUT)
                    .build()
                    .map_err(|e| IpProofError::Unreachable {
                        url: url.to_string(),
                        detail: format!("could not build an HTTP client: {e}"),
                    })?;
                Ok((client, false))
            }
        }
    }
}

impl IpProofClient for HttpIpProofClient {
    fn request_proof(
        &self,
        payer: Pubkey,
        user_type: UserType,
        source_addr: Ipv4Addr,
    ) -> Result<IpOwnershipProof, IpProofError> {
        let base_url = self
            .base_url
            .as_deref()
            .ok_or(IpProofError::NotConfigured)?;
        let url = format!("{}/v1/proof", base_url.trim_end_matches('/'));

        let (client, bound) = Self::build(source_addr, &url)?;
        debug!(%url, %payer, bound, "requesting an IP ownership proof");

        // The client is built once and reused, so a retry re-resolves through the same pool
        // rather than rebuilding a socket binding that already succeeded or already failed.
        let mut attempt = 1;
        loop {
            match attempt_request(&client, &url, payer, user_type) {
                Ok(proof) => return Ok(proof),
                Err((err, retryable)) => {
                    if !retryable || attempt == MAX_ATTEMPTS {
                        return Err(err);
                    }
                    debug!(
                        attempt,
                        error = %err,
                        "the verification request failed; trying once more"
                    );
                    thread::sleep(RETRY_DELAY);
                    attempt += 1;
                }
            }
        }
    }
}

/// One request. The flag says whether the failure is worth another attempt — see
/// [`MAX_ATTEMPTS`] for why only some are.
fn attempt_request(
    client: &reqwest::blocking::Client,
    url: &str,
    payer: Pubkey,
    user_type: UserType,
) -> Result<IpOwnershipProof, (IpProofError, bool)> {
    let unreachable = |e: reqwest::Error| {
        (
            IpProofError::Unreachable {
                url: url.to_string(),
                detail: e.to_string(),
            },
            true,
        )
    };

    let response = client
        .post(url)
        .json(&serde_json::json!({
            "payer": payer.to_string(),
            "user_type": user_type as u8,
        }))
        .send()
        .map_err(unreachable)?;

    let status = response.status();
    let body = response.text().map_err(unreachable)?;

    if !status.is_success() {
        return Err(classify_failure(status, &body));
    }

    let parsed: ProofResponse = serde_json::from_str(&body).map_err(|e| {
        (
            IpProofError::Malformed(format!("{e} (body: {})", body.trim())),
            false,
        )
    })?;
    proof_from_response(parsed).map_err(|e| (e, false))
}

/// Turns a non-success response into the reason the operator sees, and says whether another
/// attempt could change it. A 5xx could land on a healthy host behind the same name; a 4xx is
/// the service's considered answer, and retrying `rate_limited` would only make it worse.
fn classify_failure(status: reqwest::StatusCode, body: &str) -> (IpProofError, bool) {
    // The service's own reason string, when it sent one. A proxy or captive portal in the path
    // will not have, so fall back to the status and whatever body arrived.
    let err = match serde_json::from_str::<ErrorResponse>(body) {
        Ok(err) => IpProofError::Declined {
            reason: err.error,
            message: err.message,
        },
        Err(_) => IpProofError::Declined {
            reason: format!("http_{}", status.as_u16()),
            message: body.trim().chars().take(200).collect(),
        },
    };
    (err, status.is_server_error())
}

/// Converts the wire form into the struct the instruction carries, rejecting anything the
/// program would reject anyway.
fn proof_from_response(parsed: ProofResponse) -> Result<IpOwnershipProof, IpProofError> {
    let payer = Pubkey::from_str(&parsed.payer)
        .map_err(|e| IpProofError::Malformed(format!("payer '{}': {e}", parsed.payer)))?;
    let signature = Signature::from_str(&parsed.signature)
        .map_err(|e| IpProofError::Malformed(format!("signature '{}': {e}", parsed.signature)))?;
    let signature: [u8; 64] = signature.as_ref().try_into().map_err(|_| {
        IpProofError::Malformed(format!("signature '{}' is not 64 bytes", parsed.signature))
    })?;

    Ok(IpOwnershipProof {
        version: parsed.version,
        payer,
        client_ip: parsed.client_ip,
        epoch: parsed.epoch,
        user_type: parsed.user_type,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> ProofResponse {
        // A fixed payer, so a test can rebuild the same response and compare against it.
        ProofResponse {
            version: 1,
            payer: Pubkey::from([9u8; 32]).to_string(),
            client_ip: Ipv4Addr::new(203, 0, 113, 7),
            epoch: 931,
            user_type: UserType::IBRL as u8,
            signature: Signature::from([7u8; 64]).to_string(),
        }
    }

    #[test]
    fn test_proof_from_response_round_trips_the_wire_form() {
        let wire = response();
        let proof = proof_from_response(response()).expect("a well-formed response must parse");

        assert_eq!(proof.version, 1);
        assert_eq!(proof.payer.to_string(), wire.payer);
        assert_eq!(proof.client_ip, Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(proof.epoch, 931);
        assert_eq!(proof.user_type, UserType::IBRL as u8);
        assert_eq!(proof.signature, [7u8; 64]);
    }

    #[test]
    fn test_proof_from_response_rejects_a_bad_signature() {
        let err = proof_from_response(ProofResponse {
            signature: "not-base58!".to_string(),
            ..response()
        })
        .expect_err("a signature that is not base58 must not become a proof");
        assert!(matches!(err, IpProofError::Malformed(_)), "{err}");
    }

    #[test]
    fn test_proof_from_response_rejects_a_bad_payer() {
        let err = proof_from_response(ProofResponse {
            payer: "nope".to_string(),
            ..response()
        })
        .expect_err("a payer that is not a pubkey must not become a proof");
        assert!(matches!(err, IpProofError::Malformed(_)), "{err}");
    }

    /// Serves one canned response per connection, in order, and reports how many connections it
    /// actually saw. `Connection: close` on every response, so each attempt is its own
    /// connection and the count is the attempt count.
    fn canned_server(responses: Vec<String>) -> (String, std::thread::JoinHandle<usize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a test listener");
        let url = format!("http://{}", listener.local_addr().expect("a local address"));

        let handle = std::thread::spawn(move || {
            let mut served = 0;
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                // Drain the request head so the client is not answered mid-write, then reply.
                // The body is not inspected: what is under test is the retry, not the request.
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
                served += 1;
            }
            served
        });

        (url, handle)
    }

    fn http(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// The retry has to actually happen: a verifier fleet behind one name is the reason it
    /// exists, and a loop that gave up after the first 5xx would look identical in every other
    /// test.
    #[test]
    fn test_a_server_error_is_retried_and_the_second_attempt_is_used() {
        let wire = response();
        let body = format!(
            r#"{{"version":{},"payer":"{}","client_ip":"{}","epoch":{},"user_type":{},"signature":"{}"}}"#,
            wire.version, wire.payer, wire.client_ip, wire.epoch, wire.user_type, wire.signature
        );
        let (url, server) = canned_server(vec![
            http(
                "503 Service Unavailable",
                r#"{"error":"unavailable","message":"restarting"}"#,
            ),
            http("200 OK", &body),
        ]);

        let proof = HttpIpProofClient::new(Some(url))
            .request_proof(
                Pubkey::from([9u8; 32]),
                UserType::IBRL,
                Ipv4Addr::new(127, 0, 0, 1),
            )
            .expect("the second attempt must produce the proof");

        assert_eq!(proof.client_ip, wire.client_ip);
        assert_eq!(proof.epoch, wire.epoch);
        assert_eq!(server.join().expect("the server thread"), 2);
    }

    /// The mirror image: a decline must be reported from the first attempt, without a second
    /// request. `rate_limited` is the case where a retry would do harm.
    #[test]
    fn test_a_decline_is_not_retried_over_the_wire() {
        // One response only. A second attempt would find the listener gone and report
        // Unreachable instead, so the assertion below is what pins the single attempt.
        let (url, server) = canned_server(vec![http(
            "429 Too Many Requests",
            r#"{"error":"rate_limited","message":"try again in 60s"}"#,
        )]);

        let err = HttpIpProofClient::new(Some(url))
            .request_proof(
                Pubkey::from([9u8; 32]),
                UserType::IBRL,
                Ipv4Addr::new(127, 0, 0, 1),
            )
            .expect_err("a rate-limited request cannot produce a proof");

        assert!(err.to_string().contains("rate_limited"), "{err}");
        assert_eq!(server.join().expect("the server thread"), 1);
    }

    /// A 5xx is worth a second attempt, because the name may resolve to more than one host and
    /// the next one may be healthy.
    #[test]
    fn test_a_server_error_is_retryable() {
        let (err, retryable) = classify_failure(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "upstream is restarting",
        );
        assert!(retryable, "{err}");
        assert!(matches!(err, IpProofError::Declined { .. }), "{err}");
    }

    /// Retrying a rate limit only makes it worse, and the operator needs the service's own
    /// reason rather than a second identical refusal.
    #[test]
    fn test_a_decline_is_not_retryable() {
        let (err, retryable) = classify_failure(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            r#"{"error":"rate_limited","message":"try again in 60s"}"#,
        );
        assert!(!retryable, "{err}");
        match err {
            IpProofError::Declined { reason, message } => {
                assert_eq!(reason, "rate_limited");
                assert_eq!(message, "try again in 60s");
            }
            other => panic!("expected a decline carrying the service's reason, got {other}"),
        }
    }

    /// A CGNAT source is the refusal operators will actually hit, and it must not be retried.
    #[test]
    fn test_a_non_routable_source_is_not_retryable() {
        let (err, retryable) = classify_failure(
            reqwest::StatusCode::BAD_REQUEST,
            r#"{"error":"not_globally_routable","message":"100.64.0.1 is not globally routable"}"#,
        );
        assert!(!retryable, "{err}");
        assert!(err.to_string().contains("not_globally_routable"), "{err}");
    }

    /// An environment with no verifier must be distinguishable from one whose verifier is down:
    /// the first is expected during rollout, the second is worth investigating.
    #[test]
    fn test_no_configured_url_reports_not_configured() {
        let err = HttpIpProofClient::new(None)
            .request_proof(
                Pubkey::new_unique(),
                UserType::IBRL,
                Ipv4Addr::new(203, 0, 113, 7),
            )
            .expect_err("an unconfigured client cannot produce a proof");
        assert!(matches!(err, IpProofError::NotConfigured), "{err}");
    }
}
