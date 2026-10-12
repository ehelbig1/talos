`SecretsResolver::force_refresh_vault_paths` returns `ForcedRefresh`
(`Refreshed`, `RefusedByProvider`, `ProviderUnreachable`, `Failed`,
`NothingToRefresh`) instead of `bool`. **Breaking** for an implementor of the
trait. Only `Refreshed` retries the node, as `true` did; the failure the node
carries now says which of the others it was, so a token endpoint that could
not be reached is no longer reported as a refusal that needs re-authorising.
