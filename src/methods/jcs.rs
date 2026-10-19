//! The JSON Canonicalization Scheme (JCS, [RFC 8785]) over [`serde_json::Value`].
//!
//! JCS serializes JSON deterministically: object members sorted by the UTF-16 code units of
//! their names, recursively; no whitespace; strings escaped as ECMAScript's `JSON.stringify`
//! does; numbers in ECMAScript's `Number.prototype.toString` form. `did:jwk` uses it so that one
//! key always yields one DID, the same as in every other JCS implementation.
//!
//! [RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785

use serde_json::{Number, Value};

/// A JSON number JCS cannot encode, because it has no finite `f64` value (RFC 8785 §3.2.2.3
/// reads every number as an IEEE 754 double). `serde_json` only keeps such a number, `1e400`
/// say, when its `arbitrary_precision` feature is on, which another crate of the build can do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnsupportedNumber(pub(crate) String);

/// The canonical form of `value` (RFC 8785 §3.2).
///
/// # Errors
///
/// [`UnsupportedNumber`] for a number anywhere in `value` that has no finite `f64` value.
pub(crate) fn to_string(value: &Value) -> Result<String, UnsupportedNumber> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

fn write_value(out: &mut String, value: &Value) -> Result<(), UnsupportedNumber> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        // Integers beyond 2^53 lose precision, which is what JCS specifies.
        Value::Number(number) => write_number(out, finite(number)?),
        Value::String(string) => write_string(out, string),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut members: Vec<_> = members.iter().collect();
            // `serde_json`'s `preserve_order` keeps insertion order, so sort explicitly.
            members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (index, (name, member)) in members.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, name);
                out.push(':');
                write_value(out, member)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The `f64` value of `number`, which always exists without `arbitrary_precision`.
fn finite(number: &Number) -> Result<f64, UnsupportedNumber> {
    number
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(|| UnsupportedNumber(number.to_string()))
}

/// A string as RFC 8785 §3.2.2.2 escapes it: `"` and `\`, `\b`, `\t`, `\n`, `\f`, `\r`, any
/// other control character as `\u00xx` in lowercase hex, and nothing else. That is exactly
/// `serde_json`'s escaping.
fn write_string(out: &mut String, string: &str) {
    out.push_str(&serde_json::to_string(string).expect("a string serializes"));
}

/// A finite number in the form of ECMAScript's `Number.prototype.toString` (RFC 8785
/// §3.2.2.3, ECMA-262 `Number::toString`).
fn write_number(out: &mut String, value: f64) {
    if value == 0.0 {
        // Both zeros.
        out.push('0');
        return;
    }
    if value.is_sign_negative() {
        out.push('-');
    }
    let magnitude = value.abs();
    // ECMA-262 takes the fewest digits `k` that round-trip, which `{:e}` finds. Of the `k`-digit
    // decimals that round-trip, it takes the one closest to the value, and the even one on a
    // tie; `{:e}` breaks ties the other way, while exact formatting rounds half to even. At a
    // power of two, where the round-trip interval is narrower below the value, the closest one
    // can fall outside it, and the shortest one is kept.
    let shortest = format!("{magnitude:e}");
    let k = shortest.split_once('e').map_or(0, |(mantissa, _)| {
        mantissa.bytes().filter(u8::is_ascii_digit).count()
    });
    let rounded = format!("{magnitude:.*e}", k.saturating_sub(1));
    let scientific = if rounded.parse::<f64>() == Ok(magnitude) {
        rounded
    } else {
        shortest
    };
    // `d[.ddd]e<exponent>`.
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("`{:e}` writes an exponent");
    let exponent: i32 = exponent.parse().expect("the exponent is an integer");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    // `s` has no trailing zeros; neither form writes any, but exact rounding could carry.
    let digits = digits.trim_end_matches('0');
    let k = i32::try_from(digits.len()).expect("at most 17 digits");
    // The decimal point sits after the `n`-th digit: the value is 0.ddd × 10^n.
    let n = exponent + 1;
    let zeros = |count: i32| "0".repeat(usize::try_from(count).unwrap_or_default());
    if k <= n && n <= 21 {
        out.push_str(digits);
        out.push_str(&zeros(n - k));
    } else if 0 < n && n <= 21 {
        let (integer, fraction) = digits.split_at(usize::try_from(n).expect("n is positive"));
        out.push_str(integer);
        out.push('.');
        out.push_str(fraction);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.push_str(&zeros(-n));
        out.push_str(digits);
    } else {
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        out.push(if n - 1 < 0 { '-' } else { '+' });
        out.push_str(&(n - 1).unsigned_abs().to_string());
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{to_string, write_number};

    fn number(value: f64) -> String {
        let mut out = String::new();
        write_number(&mut out, value);
        out
    }

    /// RFC 8785 Appendix B, "Number Serialization Samples" (NaN and Infinity are not JSON).
    #[test]
    fn number_serialization_samples() {
        for (bits, expected) in [
            (0x0000_0000_0000_0000_u64, "0"),
            (0x8000_0000_0000_0000, "0"),
            (0x0000_0000_0000_0001, "5e-324"),
            (0x8000_0000_0000_0001, "-5e-324"),
            (0x7fef_ffff_ffff_ffff, "1.7976931348623157e+308"),
            (0xffef_ffff_ffff_ffff, "-1.7976931348623157e+308"),
            (0x4340_0000_0000_0000, "9007199254740992"),
            (0xc340_0000_0000_0000, "-9007199254740992"),
            (0x4430_0000_0000_0000, "295147905179352830000"),
            (0x44b5_2d02_c7e1_4af5, "9.999999999999997e+22"),
            (0x44b5_2d02_c7e1_4af6, "1e+23"),
            (0x44b5_2d02_c7e1_4af7, "1.0000000000000001e+23"),
            (0x444b_1ae4_d6e2_ef4e, "999999999999999700000"),
            (0x444b_1ae4_d6e2_ef4f, "999999999999999900000"),
            (0x444b_1ae4_d6e2_ef50, "1e+21"),
            (0x3eb0_c6f7_a0b5_ed8c, "9.999999999999997e-7"),
            (0x3eb0_c6f7_a0b5_ed8d, "0.000001"),
            (0x41b3_de43_5555_5553, "333333333.3333332"),
            (0x41b3_de43_5555_5554, "333333333.33333325"),
            (0x41b3_de43_5555_5555, "333333333.3333333"),
            (0x41b3_de43_5555_5556, "333333333.3333334"),
            (0x41b3_de43_5555_5557, "333333333.33333343"),
            (0xbecb_f647_612f_3696, "-0.0000033333333333333333"),
        ] {
            assert_eq!(number(f64::from_bits(bits)), expected, "{bits:016x}");
        }
        // The samples of the JCS reference test data README.
        assert_eq!(
            number(f64::from_bits(0x4340_0000_0000_0001)),
            "9007199254740994"
        );
        assert_eq!(
            number(f64::from_bits(0x4340_0000_0000_0002)),
            "9007199254740996"
        );
        // A value exactly halfway between two shortest candidates, 1381326561846934.25, takes
        // the even one, as ECMAScript does.
        assert_eq!(
            number(f64::from_bits(0xc313_a13c_9c26_9a59)),
            "-1381326561846934.2"
        );
        // Each branch of `Number::toString`.
        for (value, expected) in [
            (1.0, "1"),
            (-56.0, "-56"),
            (4.5, "4.5"),
            (0.002, "0.002"),
            (1e-7, "1e-7"),
            (1.5e-7, "1.5e-7"),
            (1e30, "1e+30"),
            (123_456_789_012_345_680_000.0, "123456789012345680000"),
        ] {
            assert_eq!(number(value), expected);
        }
    }

    /// RFC 8785 §3.2.2 and §3.2.4: the sample object and its canonical UTF-8 bytes.
    #[test]
    fn rfc_sample() {
        let input: Value = serde_json::from_str(
            r#"{
              "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
              "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
              "literals": [null, true, false]
            }"#,
        )
        .unwrap();
        let bytes = [
            "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72",
            "75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a",
            "5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31",
            "65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37",
            "5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30",
            "30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d",
        ]
        .join(" ")
        .split(' ')
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect::<Vec<u8>>();
        assert_eq!(to_string(&input).unwrap().as_bytes(), bytes);
    }

    /// The test data of the JCS reference implementation that RFC 8785 Appendix G points to
    /// (`cyberphone/json-canonicalization`, `testdata/input` and `testdata/output`).
    #[test]
    fn reference_test_data() {
        for (input, output) in [
            (
                r#"[56, {"d": true, "10": null, "1": [ ]}]"#,
                r#"[56,{"1":[],"10":null,"d":true}]"#,
            ),
            (
                r#"{"peach": "This sorting order", "péché": "is wrong according to French", "pêche": "but canonicalization MUST", "sin": "ignore locale"}"#,
                r#"{"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}"#,
            ),
            (
                r#"{"1": {"f": {"f": "hi","F": 5} ,"\n": 56.0}, "10": { }, "": "empty", "a": { }, "111": [ {"e": "yes","E": "no" } ], "A": { }}"#,
                r#"{"":"empty","1":{"\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}"#,
            ),
            (
                r#"{"Unnormalized Unicode":"A\u030a"}"#,
                "{\"Unnormalized Unicode\":\"A\u{30a}\"}",
            ),
            (
                r#"{"\u20ac": "Euro Sign", "\r": "Carriage Return", "\u000a": "Newline", "1": "One", "\u0080": "Control\u007f", "\ud83d\ude02": "Smiley", "\u00f6": "Latin Small Letter O With Diaeresis", "\ufb33": "Hebrew Letter Dalet With Dagesh", "</script>": "Browser Challenge"}"#,
                concat!(
                    r#"{"\n":"Newline","\r":"Carriage Return","1":"One","</script>":"Browser Challenge","#,
                    "\"\u{80}\":\"Control\u{7f}\",",
                    r#""ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😂":"Smiley","#,
                    "\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}",
                ),
            ),
        ] {
            let value: Value = serde_json::from_str(input).unwrap();
            assert_eq!(to_string(&value).unwrap(), output, "{input}");
            // The canonical form is a fixed point.
            let again: Value = serde_json::from_str(output).unwrap();
            assert_eq!(to_string(&again).unwrap(), output, "{input}");
        }
    }

    #[test]
    fn sorts_by_utf16_code_units_not_code_points() {
        // U+1F602 is the surrogate pair D83D DE02 in UTF-16, so it sorts before U+FB33, the
        // opposite of their code point (and UTF-8) order.
        let value = json!({"\u{fb33}": 1, "\u{1f602}": 2});
        assert_eq!(
            to_string(&value).unwrap(),
            "{\"\u{1f602}\":2,\"\u{fb33}\":1}"
        );
    }

    #[test]
    fn integers_are_numbers() {
        assert_eq!(
            to_string(&json!([0, -0, 9_007_199_254_740_993_u64, -3])).unwrap(),
            "[0,0,9007199254740992,-3]"
        );
    }
}
