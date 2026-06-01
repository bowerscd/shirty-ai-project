//! Async + sync dispatchers for `Request::AcmeList` and `Request::AcmeRenew`.

use ratatoskr::control::{error_codes, AcmeListResponse, Response};

use super::super::ControlState;

/// Synchronous: read the per-host snapshot from the live
/// `AcmeManager`. Returns an empty list when `[acme]` isn't
/// configured.
pub(in crate::control) fn dispatch_acme_list(state: &ControlState) -> Response {
    let Some(acme) = state.acme.as_ref() else {
        return Response::AcmeList(AcmeListResponse { hosts: Vec::new() });
    };
    Response::AcmeList(AcmeListResponse {
        hosts: acme.list_managed(),
    })
}

/// Async: kick the renewer for `hostname` and wait for the result.
/// Bounded by a 5-minute deadline so a stuck CA never hangs the
/// control socket. Returns `acme_not_configured` when `[acme]` is
/// absent and `acme_unknown_host` when the hostname doesn't match a
/// `cert = "acme"` route.
pub(in crate::control) async fn dispatch_acme_renew(
    hostname: &str,
    state: &ControlState,
) -> Response {
    let Some(acme) = state.acme.as_ref() else {
        return Response::Error {
            code: error_codes::ACME_NOT_CONFIGURED.into(),
            message: "this daemon has no [acme] section configured; \
                      add one and reload to enable ACME issuance"
                .into(),
        };
    };
    let deadline = std::time::Duration::from_secs(300);
    match tokio::time::timeout(deadline, acme.force_renew(hostname)).await {
        Ok(Ok(())) => Response::AcmeRenewed {
            hostname: hostname.to_ascii_lowercase(),
            success: true,
        },
        Ok(Err(e)) => {
            let s = e.to_string();
            let code = if s.contains("no ACME-managed route") {
                error_codes::ACME_UNKNOWN_HOST
            } else {
                error_codes::ACME_RENEW_FAILED
            };
            Response::Error {
                code: code.into(),
                message: s,
            }
        }
        Err(_) => Response::Error {
            code: error_codes::ACME_RENEW_FAILED.into(),
            message: format!("ACME renewer did not complete within {deadline:?}"),
        },
    }
}
