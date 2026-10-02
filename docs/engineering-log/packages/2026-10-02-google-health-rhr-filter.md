# Google Health reader: the resting-heart-rate filter (2026-10-02)

Follow-up to `2026-10-02-google-health-connection.md`, from the first call
against the real API.

**What the first live call showed.** The connection, the vault header
resolution and the sleep and steps requests all worked. The resting-heart-rate
request was refused: `400 INVALID_ARGUMENT`, `Invalid data point filter:
INVALID_DATA_POINT_FILTER_DATA_TYPE_RESTRICTION`. The reader reported it under
`unavailable` and still returned the other two readings, as designed.

**Cause.** The filter named the member `dailyRestingHeartRate.date` — the
camelCase name the JSON response uses. Filter members are snake_case:
`daily_resting_heart_rate.date`. Sleep and steps were unaffected only because
their names are single words. Google's reference shows a camelCase example for
a daily type, so the reference is not a reliable guide here; the API's answer
is.

**Rule for the next reader of this API.** Path segments are kebab-case
(`daily-resting-heart-rate`), filter members snake_case, JSON fields camelCase.

**Verified live.** After the change all three requests answer 200 on the
operator's connection. The account had no readings yet (`nothing_recorded:
true`), so the RESPONSE shapes with data — sleep stages, step intervals, the
heart-rate value — are still unverified against the real API.

**Found, not fixed.** A module installed from the catalog stores no
`dependencies`, so `hot_update_module` on the installed copy fails to compile a
template that uses a crate (`chrono` here) unless the caller restates the
dependency map. A reinstall from the catalog is unaffected.
