A path minted at dispatch can be told from a stored one, and asked about
without minting. `talos-workflow-job-protocol`: `dispatch_mint`,
`DispatchMint`, `MintScheme`, `grant_reaches_minted_paths`,
`GITHUB_APP_SCHEME`. `talos-workflow-engine-core`: `MintReadiness`, and a
required `mint_readiness` method on `GcpImpersonationTokenProvider` and
`GithubInstallationTokenProvider` (an implementer outside this workspace must
add it). `vault_resolver::check_vault_refs_resolvable` returns the new
`VaultResolverError::MintedAtDispatch` for an absent mint path instead of
`SecretNotResolved`, whose text advised storing a secret there.
