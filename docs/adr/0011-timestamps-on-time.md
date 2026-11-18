# ADR 0011: The upper layer's timestamps are a crate-owned `Timestamp` built on `time`, not `chrono`

- Status: accepted
- Date: 2026-11-18

## Context

RUSTSEC-2026-0543 marks `chrono` as unmaintained, with no patched version, and recommends `jiff`
or `time`. #180 ignored the advisory to keep the Audit workflow green; #181 is the follow-up.

`chrono` came in with the `vc` feature and was the type of every timestamp in the upper layer:
`chrono::DateTime<Utc>` in the credential models of VCDM 1.1 and 2.0, the JWT claim setters, the
SD-JWT VC, Status List Token, DID configuration and Linked VP builders, `TimeOptions` and the
time fields of the validation errors. The lower layer keeps `NumericDate` seconds in `JwtClaims`
and has no date-time crate.

A spike on #181 read the 54 distinct timestamps of the repository (tests, vectors, fuzz seeds,
documentation) and 25 edge cases with `chrono` as the crate used it, `jiff` 1.0 and `time` 0.3.55,
comparing the instant each reads and the text each writes back:

- `time`'s RFC 3339 parser accepts and refuses what `chrono`'s `parse_from_rfc3339` does, on
  every input but the leap second (`:60`, which `time` reads as `:59.999999999`). Its range ends
  at 9999-12-31.
- `jiff`'s `Timestamp` ends at 9999-12-30, so `9999-12-31T23:59:59Z`, the "no expiration" value
  RFC 5280 §4.1.2.5 gives certificates and some issuers copy into `exp` or `validUntil`, would no
  longer parse. Its parser accepts forms RFC 3339 does not (minute precision, comma fractions,
  offsets of 24 hours or with seconds).
- Both write fractional seconds with as few digits as needed (`.5Z` where `chrono` writes
  `.500Z`), and `Z` where `chrono`'s `to_rfc3339()` wrote `+00:00`.

## Decision

1. **`time`, with `default-features = false` and `formatting`, `parsing` and `std`.** It parses
   exactly what the crate parsed, covers the dates issuers write, and is maintained. It brings
   `time-core`, `deranged`, `num-conv` and `powerfmt`; licenses MIT OR Apache-2.0; MSRV 1.88,
   below the crate's.

2. **A crate-owned `vc::Timestamp` is the public type.** Every public timestamp is a
   `Timestamp`: an instant in UTC, to the nanosecond, from `0000-01-01T00:00:00Z` to
   `9999-12-31T23:59:59.999999999Z`, the instants RFC 3339 can write. It serializes as RFC 3339
   in UTC with as many fractional digits as needed, parses RFC 3339 with any offset, converts
   to and from `NumericDate` seconds (`from_unix_seconds`, `unix_seconds`) and, where both
   reach the instant, `SystemTime` (`time`'s own conversion panics where they do not), and
   adds and subtracts `core::time::Duration` (checked, saturating, or panicking on overflow as
   `SystemTime` does). The public API names no date-time crate, so the next change of crate does
   not break callers again, and no field needs a serde attribute. It lives in `vc`, the module
   every upper-layer feature implies, and in the prelude.

3. **A clean break, without a `chrono` compatibility feature.** The change is breaking (`!`, a
   minor version before 1.0) either way, and keeping `chrono` optional would keep the advisory
   on the ignore lists. Callers convert through Unix seconds or RFC 3339 text, which both crates
   speak.

4. **Out-of-range times saturate where they are compared.** A `NumericDate` outside the range
   of `Timestamp` is out of range where a credential or claim must carry it (as before, beyond
   `chrono`'s wider range), and as far in the past or future as its sign where a Status List
   Token's `iat` or `exp` is compared with the validation time, so a far-future `exp` does not
   read as expired. A leeway or a key binding `max_age` beyond the range saturates.

## Consequences

- Every public timestamp type changes from `chrono::DateTime<Utc>` to `vc::Timestamp`:
  `Credential`, `CredentialV2`, the `JwtClaims` conversions and setters, the SD-JWT VC, Status
  List Token, DID configuration and Linked VP types and builders, `TimeOptions`, and the error
  variants that carry times. `TimestampError` is new.
- Newly issued credentials write fractional seconds with as few digits as needed and `Z` for
  UTC, as VCDM's `dateTimeStamp` allows; the instants are unchanged, and validation of existing
  credentials is not affected. Error messages print times with `Z`.
- Credential fields parse RFC 3339 only. `chrono`'s serde implementation also accepted an offset
  without a colon (`+0200`) and a trailing ` UTC`, which are not RFC 3339 and which the
  `NumericDate` mapping already refused; no vector uses them.
- A `NumericDate` after year 9999 no longer converts to a timestamp; `chrono` reached year
  262143.
- `chrono` leaves the dependency tree of the library and the fuzz crate, and RUSTSEC-2026-0543
  leaves the ignore lists of `deny.toml` and `osv-scanner.toml`. The layer-boundary check now
  asserts that the lower layer does not pull in `time`.
