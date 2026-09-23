//! Linking an item: the decisions, kept pure so they are testable.
//!
//! The IO shell (HTTP, the vault write) lives in `controller/src/cli.rs`; this
//! module owns what must be DECIDED — which source is legitimate for which
//! environment, which vault paths the credential lands on, and what may be
//! printed. Those three are the parts a mistake is expensive in, and none of
//! them needs a network or a database to exercise.
//!
//! WHY THE EXCHANGE IS CONTROLLER-SIDE AT ALL. `/item/public_token/exchange`
//! RETURNS a long-lived credential in its response body, and a WASM module's
//! response becomes `module_executions.output_data`. A module may cause a
//! credential to be used and must never be the thing that RECEIVES one. The
//! data reads (`/transactions/sync`, `/accounts/balance/get`) are the opposite
//! case and belong in a module, reaching their credential through `vault://`
//! body substitution.

use crate::config::PlaidEnv;

/// The vault path prefix every Plaid secret lives under.
///
/// ONE home, because two readers of a credential path that disagree is a
/// credential that cannot be found — the module's `allowed_secrets` grant, the
/// module's `vault://` references and this writer all derive from here.
pub const PLAID_VAULT_PREFIX: &str = "plaid/";

/// App credentials. A module needs BOTH in its request body — Plaid takes
/// `client_id` and `secret` as body fields on every endpoint — so they are
/// vault secrets rather than controller-only env, even though the controller
/// also reads them from the environment for its own calls.
pub const PLAID_CLIENT_ID_PATH: &str = "plaid/client_id";
pub const PLAID_SECRET_PATH: &str = "plaid/secret";

/// The `allowed_secrets` grant a Plaid-reading module needs.
pub const PLAID_SECRETS_GRANT: &str = "plaid/*";

/// An item id is chosen by PLAID, not by us, and it is interpolated into a
/// vault path — so it is untrusted input to a path, which is the shape that
/// deserves a validator rather than a comment. Plaid's ids are opaque
/// alphanumerics; anything else is refused rather than sanitised, because a
/// silently-rewritten path is a credential nobody can find later.
const MAX_ITEM_ID: usize = 128;

/// Where an item's access token is stored.
///
/// # Errors
/// When the item id is empty, over [`MAX_ITEM_ID`] bytes, or carries anything
/// outside `[A-Za-z0-9_-]` — a `/` would silently re-root the path.
pub fn access_token_path(item_id: &str) -> Result<String, String> {
    if item_id.is_empty() {
        return Err("Plaid returned an empty item id".to_string());
    }
    if item_id.len() > MAX_ITEM_ID {
        return Err(format!(
            "Plaid item id is {} bytes; the cap is {MAX_ITEM_ID}",
            item_id.len()
        ));
    }
    if let Some(bad) = item_id
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '_' && *c != '-')
    {
        return Err(format!(
            "Plaid item id carries {bad:?}, which is not permitted in a vault path"
        ));
    }
    Ok(format!("{PLAID_VAULT_PREFIX}access_token/{item_id}"))
}

/// How the `public_token` being exchanged was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSource {
    /// Minted by `/sandbox/public_token/create` — no browser, no real bank.
    Sandbox {
        institution_id: String,
        products: Vec<String>,
    },
    /// Handed over by a human who completed Plaid Link in a browser. The only
    /// way a PRODUCTION item can be linked.
    ///
    /// The token itself is deliberately NOT held here: it is read straight from
    /// the argument into the exchange, so it never lands in a struct that could
    /// grow a `Debug` derive.
    Browser,
}

/// Why a link attempt was refused before any network call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRefusal {
    /// `--sandbox` against a production configuration.
    SandboxSourceInProduction,
    /// A browser token was asked for but not supplied.
    MissingPublicToken,
}

impl LinkRefusal {
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::SandboxSourceInProduction => concat!(
                "--sandbox refused: PLAID_ENV is `production`, where ",
                "/sandbox/public_token/create does not exist. A production item is ",
                "linked by a human completing Plaid Link in a browser; pass the ",
                "resulting token with --public-token.",
            )
            .to_string(),
            Self::MissingPublicToken => concat!(
                "--public-token needs a value. Obtain one by completing Plaid Link ",
                "(Hosted Link or an embedded Link component), or use --sandbox ",
                "against a sandbox configuration.",
            )
            .to_string(),
        }
    }
}

/// Decide whether this source may be used against this environment.
///
/// Sandbox-in-production is the refusal that matters: the endpoint is absent
/// there, so without this the operator would send PRODUCTION app credentials to
/// a URL that rejects them, and read the failure as a configuration problem.
///
/// The reverse — a browser token against a sandbox configuration — is NOT
/// refused: it is exactly what a sandbox Link flow produces, and refusing it
/// would block the one path that proves the production shape before using it.
///
/// # Errors
/// [`LinkRefusal`] when the pairing is not legitimate.
pub fn check_source(env: PlaidEnv, source: &LinkSource) -> Result<(), LinkRefusal> {
    match source {
        LinkSource::Sandbox { .. } if env != PlaidEnv::Sandbox => {
            Err(LinkRefusal::SandboxSourceInProduction)
        }
        _ => Ok(()),
    }
}

/// What a successful link may TELL the operator.
///
/// Everything here is an identifier or a count. The access token is not a field
/// of this struct, so the renderer cannot print it by accident and a future
/// field cannot be added without deciding to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkReport {
    pub env: &'static str,
    pub item_id: String,
    pub access_token_path: String,
    pub accounts: usize,
    /// Account names as Plaid returns them, so the operator can confirm the
    /// right institution was linked. Names, never numbers: a `mask` is the last
    /// digits of an account number and has no business on a terminal.
    pub account_names: Vec<String>,
}

impl LinkReport {
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = format!(
            "linked a Plaid item ({} environment)\n\n  item_id           {}\n",
            self.env, self.item_id
        );
        s.push_str(&format!("  accounts          {}\n", self.accounts));
        for n in &self.account_names {
            s.push_str(&format!("                    · {n}\n"));
        }
        s.push_str("\nvault paths written (values never printed):\n");
        s.push_str(&format!("  {PLAID_CLIENT_ID_PATH}\n"));
        s.push_str(&format!("  {PLAID_SECRET_PATH}\n"));
        s.push_str(&format!("  {}\n", self.access_token_path));
        s.push_str(&format!(
            "\na module reads these with `{PLAID_SECRETS_GRANT}` in allowed_secrets and a\n\
             `vault://<path>` reference in its JSON request body — the guest never holds\n\
             the value.\n"
        ));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sandbox_source_is_refused_against_production() {
        let src = LinkSource::Sandbox {
            institution_id: "ins_109508".to_string(),
            products: vec!["transactions".to_string()],
        };
        assert_eq!(
            check_source(PlaidEnv::Production, &src),
            Err(LinkRefusal::SandboxSourceInProduction)
        );
        // …and the message tells the operator what to do instead, rather than
        // only what went wrong.
        let m = LinkRefusal::SandboxSourceInProduction.message();
        assert!(m.contains("--public-token"), "{m}");
        assert!(m.contains("browser"), "{m}");
    }

    #[test]
    fn a_sandbox_source_is_permitted_against_sandbox() {
        let src = LinkSource::Sandbox {
            institution_id: "ins_109508".to_string(),
            products: vec!["transactions".to_string()],
        };
        assert_eq!(check_source(PlaidEnv::Sandbox, &src), Ok(()));
    }

    /// The CONTROL for the refusal above: a browser token is legitimate in BOTH
    /// environments. Refusing it in sandbox would block the one flow that
    /// proves the production shape before anyone depends on it.
    #[test]
    fn a_browser_token_is_permitted_in_either_environment() {
        assert_eq!(
            check_source(PlaidEnv::Sandbox, &LinkSource::Browser),
            Ok(())
        );
        assert_eq!(
            check_source(PlaidEnv::Production, &LinkSource::Browser),
            Ok(())
        );
    }

    #[test]
    fn an_item_id_cannot_re_root_the_vault_path() {
        // The one that matters: a `/` would move the credential somewhere the
        // module's grant does not cover, or over another secret entirely.
        let e = access_token_path("../../anthropic/api_key").expect_err("must refuse");
        assert!(e.contains("not permitted in a vault path"), "{e}");
        for bad in ["a b", "a\nb", "a*b", "café", "a/b"] {
            assert!(access_token_path(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(access_token_path("").is_err());
        assert!(access_token_path(&"a".repeat(MAX_ITEM_ID + 1)).is_err());
    }

    #[test]
    fn a_normal_item_id_lands_under_the_shared_prefix() {
        let p = access_token_path("xyz_ABC-123").expect("valid");
        assert_eq!(p, "plaid/access_token/xyz_ABC-123");
        assert!(p.starts_with(PLAID_VAULT_PREFIX));
        // Every path this writer produces must be covered by the grant a
        // module is given — otherwise the credential is written somewhere the
        // reader is not allowed to look.
        let grant_prefix = PLAID_SECRETS_GRANT.trim_end_matches('*');
        for path in [PLAID_CLIENT_ID_PATH, PLAID_SECRET_PATH, p.as_str()] {
            assert!(
                path.starts_with(grant_prefix),
                "{path} outside {grant_prefix}"
            );
        }
    }

    #[test]
    fn the_report_names_paths_and_never_a_token() {
        let r = LinkReport {
            env: "sandbox",
            item_id: "item123".to_string(),
            access_token_path: access_token_path("item123").expect("valid"),
            accounts: 2,
            account_names: vec!["Plaid Checking".to_string(), "Plaid Saving".to_string()],
        };
        let out = r.render();
        assert!(out.contains("item123"));
        assert!(out.contains("plaid/access_token/item123"));
        assert!(out.contains("Plaid Checking"));
        assert!(out.contains("values never printed"));
        // The PATH `plaid/secret` is printed and must be — it is a location,
        // not a value. What must never appear is a token, and Plaid's tokens
        // are prefix-shaped, which is what makes this assertable:
        // `access-sandbox-…`, `access-production-…`, `public-sandbox-…`.
        //
        // (The first version of this test asserted on the bare word "secret"
        // and failed on the path it exists to print — a guard has to name the
        // thing it forbids, not a word that appears in the thing it requires.)
        assert!(
            out.contains(PLAID_SECRET_PATH),
            "the path must be printed: {out}"
        );
        for leak in [
            "access-sandbox",
            "access-production",
            "public-sandbox",
            "public-production",
        ] {
            assert!(
                !out.to_lowercase().contains(leak),
                "the report must not carry a {leak:?} token: {out}"
            );
        }
    }
}
