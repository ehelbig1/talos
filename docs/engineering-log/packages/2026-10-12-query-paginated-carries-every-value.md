# `query_paginated` returns every value it read (2026-10-12)

`query_paginated` returned `null` for a `timestamp`, a `numeric`, a
`smallint`, a `date` and every array, with no error. A report built on it
read as "no data".

## Measured

On the reference deployment, before the change:

```sql
SELECT now()::timestamp(0) AS ts, round(1.5::numeric, 0) AS n,
       to_char(now(), 'YYYY') AS y, 7::int AS i,
       ARRAY['a','b'] AS arr, 3::smallint AS s
```

returned `ts`, `n`, `arr` and `s` as `null` beside `y: "2026"` and `i: 7`.

The handler tried eight Rust types in turn against each column (`String`,
`i64`, `i32`, `f64`, `bool`, `Uuid`, `DateTime<Utc>`, `serde_json::Value`)
and wrote `null` when none decoded. Its comment said "fall back to text
representation"; there was no such fallback. `sqlx` matches a Rust type to
exactly the Postgres types it is declared compatible with, so `timestamp`
(not `timestamptz`), `numeric`, `int2`, `float4`, `date`, `time`,
`interval`, arrays and enums were all `null`.

## Decided

* **One encoder, `talos_advanced_repository::row_json::row_to_json`.** It
  reads the column's type and decodes that type. A SQL NULL is `null`; a
  present value is never `null`.
* **A type with no rendering refuses the query** and the error names the
  column and the type, with the cast to write (`col::text`). Fail closed: the
  alternative was a `null` or a placeholder string in a column of data.
* **`numeric` is a string** holding the exact decimal. A JSON number is read
  as a double by most clients, which rounds past 15 digits.
* **`numeric` is decoded by hand** from Postgres's binary send format (a
  header of four 16-bit fields, then base-10000 digits). The workspace has no
  decimal crate and one type did not justify adding one. The decoder is held
  to the server: the test casts 24 literals to `numeric`, and compares what
  the decoder produced with `value::text` from the same row.
* **A float JSON cannot hold** (`NaN`, the infinities) is the string Postgres
  prints. `serde_json` writes those as `null`, which would be the same defect.
* **`interval` is `{months, days, microseconds}`**, the three fields Postgres
  stores. Rendering it as text means choosing an `IntervalStyle`.
* **Carried now:** `bool`, `int2/4/8`, `float4/8`, text types, `uuid`,
  `timestamptz`, `timestamp`, `date`, `time`, `interval`, `json/jsonb`,
  `numeric`, enum labels, and arrays of the scalars a report uses.

## Behaviour that changed for a caller

* A `numeric` that used to be `null` is a string, not a number.
* A query that selects a column of a type with no rendering (`inet`, `bytea`,
  ranges, `"char"`, domains) is refused where it used to return `null` for
  that column. `SELECT *` over a table with such a column needs the column
  cast or left out. A NULL of such a type is still `null`.

## Tests

* `talos-advanced-repository/tests/paginated_row_json.rs` (store:
  `selfcontained`), through the real `execute_paginated_select`:
  every carried type against its expected JSON, with only the SQL NULLs
  allowed to be `null`; the `numeric` comparison with the server; the
  refusal for `inet`, its cast, and a NULL `inet`.
* `row_json` unit tests: the decoder on hand-built bytes, malformed bytes
  refused, non-finite floats.
* The handler's refusal sentence names the column, the type and the cast.
* With the old behaviour put back (an undecoded column is `null`), the
  first and third database tests fail.

## Stated limits

* The handler itself is not driven end to end by a test; it needs an
  `McpState`. What is tested is the encoder it calls and the sentence it
  returns.
* `next_cursor` is still the encoded value of the cursor column, so a cursor
  on a `timestamp` column now works where it produced the string `"null"`.
  That path is not tested here.

## Deliberately not done

* **`SELECT row_to_json(q)` on the server.** It would cover every type with
  no decoder, but it changes the statement the role runs, moves `numeric`
  back to a JSON number, and this tool's statement shape is what six
  packages of gates were written against.
* **A decimal crate** (`rust_decimal` or `bigdecimal` through `sqlx`).
