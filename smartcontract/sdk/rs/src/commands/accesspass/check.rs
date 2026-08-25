//! The AccessPass pre-flight shared by `doublezero connect` and the serviceability CLI.
//!
//! Both surfaces answer the same question before they send anything: does the caller hold a pass
//! the program will accept for this `client_ip`? They reach the ledger through different client
//! abstractions, so the ledger read is a closure and only the decision lives here — previously it
//! was two copies with a comment on each asking the next person to keep them in sync.

use doublezero_serviceability::state::accesspass::AccessPass;
use std::net::Ipv4Addr;

/// Reports whether the caller holds a usable AccessPass for `client_ip`.
///
/// `lookup` resolves the pass stored at a given `client_ip` for the caller's payer; `epoch` reads
/// the current ledger epoch, and is only called when `enforce_epoch` is set so the common
/// "no pass at all" answer costs one RPC.
///
/// A pass stored at [`Ipv4Addr::UNSPECIFIED`] (0.0.0.0) is valid for any client IP — that is how
/// dynamic seats, including the `EdgeSeat` passes issued by the shred oracle, are held. The
/// program accepts either the exact-IP PDA or the UNSPECIFIED one (see `create_core.rs`), so
/// probing only the exact IP would report "no valid AccessPass" for a wildcard holder and bail
/// before ever reaching the program, which would have accepted them. Hence the fallback.
///
/// `Ok(false)` rather than an error when no pass exists: the caller renders its own diagnostic
/// (the client IP and payer) before bailing, which is more use than a generic "not found".
pub fn check_accesspass<L, E>(
    client_ip: Ipv4Addr,
    enforce_epoch: bool,
    lookup: L,
    epoch: E,
) -> eyre::Result<bool>
where
    L: Fn(Ipv4Addr) -> eyre::Result<Option<AccessPass>>,
    E: FnOnce() -> eyre::Result<u64>,
{
    let accesspass = match lookup(client_ip)? {
        Some(accesspass) => Some(accesspass),
        // Already the dynamic PDA — a second identical lookup would tell us nothing.
        None if client_ip == Ipv4Addr::UNSPECIFIED => None,
        None => lookup(Ipv4Addr::UNSPECIFIED)?,
    };

    let Some(accesspass) = accesspass else {
        return Ok(false);
    };

    if !enforce_epoch {
        return Ok(true);
    }
    Ok(accesspass.last_access_epoch >= epoch()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use doublezero_serviceability::state::{
        accesspass::{AccessPassStatus, AccessPassType},
        accounttype::AccountType,
    };
    use solana_sdk::pubkey::Pubkey;
    use std::cell::RefCell;

    const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const EPOCH: u64 = 100;

    fn pass(client_ip: Ipv4Addr, last_access_epoch: u64) -> AccessPass {
        AccessPass {
            account_type: AccountType::AccessPass,
            owner: Pubkey::new_unique(),
            bump_seed: 0,
            accesspass_type: AccessPassType::Prepaid,
            client_ip,
            user_payer: Pubkey::new_unique(),
            last_access_epoch,
            connection_count: 0,
            status: AccessPassStatus::Connected,
            mgroup_pub_allowlist: vec![],
            mgroup_sub_allowlist: vec![],
            flags: 0,
            tenant_allowlist: vec![],
            unicast_user_count: 0,
            max_unicast_users: 1,
            multicast_user_count: 0,
            max_multicast_users: 1,
        }
    }

    /// Records the IPs looked up, so the tests can assert the fallback happened (or did not).
    fn recording_lookup<'a>(
        seen: &'a RefCell<Vec<Ipv4Addr>>,
        answer: impl Fn(Ipv4Addr) -> Option<AccessPass> + 'a,
    ) -> impl Fn(Ipv4Addr) -> eyre::Result<Option<AccessPass>> + 'a {
        move |ip| {
            seen.borrow_mut().push(ip);
            Ok(answer(ip))
        }
    }

    #[test]
    fn specific_ip_pass_is_found_without_probing_the_dynamic_pda() {
        let seen = RefCell::new(vec![]);
        let found = check_accesspass(
            CLIENT_IP,
            true,
            recording_lookup(&seen, |ip| (ip == CLIENT_IP).then(|| pass(ip, EPOCH))),
            || Ok(EPOCH),
        )
        .unwrap();

        assert!(found);
        assert_eq!(*seen.borrow(), vec![CLIENT_IP]);
    }

    #[test]
    fn falls_back_to_a_valid_dynamic_pass() {
        let seen = RefCell::new(vec![]);
        let found = check_accesspass(
            CLIENT_IP,
            true,
            recording_lookup(&seen, |ip| {
                (ip == Ipv4Addr::UNSPECIFIED).then(|| pass(ip, EPOCH))
            }),
            || Ok(EPOCH),
        )
        .unwrap();

        assert!(found);
        assert_eq!(*seen.borrow(), vec![CLIENT_IP, Ipv4Addr::UNSPECIFIED]);
    }

    #[test]
    fn no_pass_at_either_pda_is_not_an_error() {
        let seen = RefCell::new(vec![]);
        let found = check_accesspass(CLIENT_IP, true, recording_lookup(&seen, |_| None), || {
            panic!("the epoch is not read when there is no pass")
        })
        .unwrap();

        assert!(!found);
        assert_eq!(*seen.borrow(), vec![CLIENT_IP, Ipv4Addr::UNSPECIFIED]);
    }

    #[test]
    fn an_epoch_expired_dynamic_pass_does_not_count() {
        let seen = RefCell::new(vec![]);
        let found = check_accesspass(
            CLIENT_IP,
            true,
            recording_lookup(&seen, |ip| {
                (ip == Ipv4Addr::UNSPECIFIED).then(|| pass(ip, EPOCH - 1))
            }),
            || Ok(EPOCH),
        )
        .unwrap();

        assert!(!found);
    }

    #[test]
    fn an_expired_pass_still_counts_when_the_epoch_is_not_enforced() {
        let seen = RefCell::new(vec![]);
        let found = check_accesspass(
            CLIENT_IP,
            false,
            recording_lookup(&seen, |ip| {
                (ip == Ipv4Addr::UNSPECIFIED).then(|| pass(ip, EPOCH - 1))
            }),
            || panic!("the epoch is not read when it is not enforced"),
        )
        .unwrap();

        assert!(found);
    }

    #[test]
    fn an_unspecified_client_ip_is_looked_up_once() {
        let seen = RefCell::new(vec![]);
        let found = check_accesspass(
            Ipv4Addr::UNSPECIFIED,
            true,
            recording_lookup(&seen, |_| None),
            || Ok(EPOCH),
        )
        .unwrap();

        assert!(!found);
        assert_eq!(*seen.borrow(), vec![Ipv4Addr::UNSPECIFIED]);
    }
}
