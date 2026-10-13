Action links can be minted on an address of the operator's own
(`TALOS_ACTION_LINKS_BASE_URL`, read by `talos_config::action_links_base_url`;
`https://host[:port]` only). Unset, links go out on the public address as
before. A value that is not an https origin mints nothing: the Postgres minter
answers every request with `link_address_misconfigured` and writes no token
row, and never substitutes the public address.
