//! How an adapter's configured base address may be written — the ONE rule
//! (security review 2026-10-14, F-11; one validator 2026-10-15).
//!
//! The five adapters that take a base address from their configuration
//! (`notify-ntfy`, `notify-home-assistant`, `control-home-assistant`,
//! `capture-ntfy`, `capture-home-assistant`) are compiled on their own, so
//! they cannot link this crate. Each carries the block between the two
//! markers below, byte for byte; `talos-catalog-tests/tests/base_address_contract.rs`
//! holds every copy equal to this one, and the tests here are the rule's.
//!
//! The rule: `https://`, a non-empty authority with no `user:password@` (it
//! would carry credentials in the adapter's own request line), printable ASCII
//! only, at most 2000 bytes, no query, no fragment, and a path only where the
//! adapter takes one. The address is returned without its trailing `/`.
//! Which host it may reach is not decided here: the worker's `allowed_hosts`
//! gates every request.

// ── base address contract ───────────────────────────────────────────────────
/// A configured base address, checked (see the rule in
/// `talos_integration_helpers::base_address`). `path_allowed` is whether the
/// adapter takes a path after the host. The error names the setting, never
/// its value.
pub fn https_base(raw: &str, name: &str, path_allowed: bool) -> Result<String, String> {
    let base = raw.trim().trim_end_matches('/');
    let Some(rest) = base.strip_prefix("https://") else {
        return Err(format!("{name} must start with https://"));
    };
    let authority = rest.split('/').next().unwrap_or("");
    let ok = !authority.is_empty()
        && base.len() <= 2000
        && base.bytes().all(|b| b.is_ascii_graphic())
        && !base.contains('?')
        && !base.contains('#')
        && !authority.contains('@')
        && (path_allowed || !rest.contains('/'));
    if ok {
        Ok(base.to_string())
    } else if path_allowed {
        Err(format!(
            "{name} must be an https:// address with no query or credentials"
        ))
    } else {
        Err(format!(
            "{name} must be https://<host> with no path, query or credentials"
        ))
    }
}
// ── end base address contract ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::https_base;

    #[test]
    fn an_https_address_is_kept_without_its_trailing_slash() {
        assert_eq!(
            https_base(" https://home.example.test/ ", "BASE_URL", false).as_deref(),
            Ok("https://home.example.test")
        );
        assert_eq!(
            https_base("https://ntfy.example.test/base/", "SERVER", true).as_deref(),
            Ok("https://ntfy.example.test/base")
        );
        assert_eq!(
            https_base("https://home.example.test:8123", "BASE_URL", false).as_deref(),
            Ok("https://home.example.test:8123")
        );
    }

    #[test]
    fn a_base_with_userinfo_is_refused_with_or_without_a_path() {
        for raw in [
            "https://user:secret@home.example.test",
            "https://user@home.example.test/",
            "https://user:secret@home.example.test/base",
        ] {
            for path_allowed in [true, false] {
                let err = https_base(raw, "BASE_URL", path_allowed).unwrap_err();
                assert!(!err.contains("secret"), "the value is not echoed: {err}");
            }
        }
        // An `@` after the authority is a path character, not userinfo.
        assert!(https_base("https://home.example.test/a@b", "BASE_URL", true).is_ok());
    }

    #[test]
    fn everything_else_the_rule_refuses() {
        let refused = [
            ("http://home.example.test", "must start with https://"),
            ("home.example.test", "must start with https://"),
            ("https://", "must start with https://"),
            ("https:///path", "no query or credentials"),
            ("https://home.example.test?x=1", "no query or credentials"),
            ("https://home.example.test/#frag", "no query or credentials"),
            ("https://home.example.test/a b", "no query or credentials"),
        ];
        for (raw, why) in refused {
            let err = https_base(raw, "BASE_URL", true).unwrap_err();
            assert!(err.contains(why), "{raw}: {err}");
        }
        let long = format!("https://home.example.test/{}", "a".repeat(2000));
        assert!(https_base(&long, "BASE_URL", true).is_err());
        assert_eq!(
            https_base("https://home.example.test/base", "BASE_URL", false).unwrap_err(),
            "BASE_URL must be https://<host> with no path, query or credentials"
        );
    }
}
