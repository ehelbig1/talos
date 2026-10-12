//! A `query_paginated` row as JSON, without losing a value on the way.
//!
//! Until 2026-10-12 the handler tried eight Rust types in turn against every
//! column and wrote `null` when none decoded. `timestamp`, `numeric`, `date`,
//! `int2`, `float4` and every array are none of the eight, so a present value
//! came back as `null`: the same thing the reader sees for SQL NULL, and a
//! report built on it read as "no data".
//!
//! This encoder asks the column for its type and decodes that type. A SQL
//! NULL is `null`; a present value is never `null`; a type it cannot carry is
//! an error that names the column and the type, so the caller can cast it.

use serde_json::Value;
use sqlx::postgres::{PgRow, PgTypeKind, PgValueFormat};
use sqlx::{Column, Row, TypeInfo, ValueRef};

/// Why a row could not be turned into JSON. Both name the column, so the
/// caller can be told which one to cast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowJsonError {
    /// The encoder has no rendering for this column's type.
    UnsupportedType { column: String, type_name: String },
    /// The type is one the encoder carries and this value did not decode.
    Undecodable { column: String, type_name: String },
}

impl std::fmt::Display for RowJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedType { column, type_name } => write!(
                f,
                "column '{column}' has type {type_name}, which cannot be returned"
            ),
            Self::Undecodable { column, type_name } => write!(
                f,
                "column '{column}' ({type_name}) held a value that could not be decoded"
            ),
        }
    }
}

impl std::error::Error for RowJsonError {}

impl RowJsonError {
    /// The column the error is about.
    pub fn column(&self) -> &str {
        match self {
            Self::UnsupportedType { column, .. } | Self::Undecodable { column, .. } => column,
        }
    }

    /// The Postgres name of that column's type.
    pub fn type_name(&self) -> &str {
        match self {
            Self::UnsupportedType { type_name, .. } | Self::Undecodable { type_name, .. } => {
                type_name
            }
        }
    }
}

/// One row as a JSON object keyed by column name.
///
/// * integers, floats and booleans are JSON numbers and booleans; a float
///   that is not finite is the string Postgres prints (`"NaN"`, `"Infinity"`);
/// * `numeric` is a string holding the exact decimal Postgres prints, because
///   a JSON number read as a double would round it;
/// * `timestamptz` is RFC 3339; `timestamp`, `date` and `time` are ISO 8601
///   without an offset; `interval` is `{months, days, microseconds}`;
/// * `json` / `jsonb` are embedded; `uuid`, text types and enum labels are
///   strings; an array of any scalar above is a JSON array.
///
/// Two columns with one name keep the later one, as before.
pub fn row_to_json(row: &PgRow) -> Result<serde_json::Map<String, Value>, RowJsonError> {
    let mut object = serde_json::Map::new();
    for column in row.columns() {
        let index = column.ordinal();
        let name = column.name();
        let type_info = column.type_info();
        let type_name = type_info.name();
        let undecodable = || RowJsonError::Undecodable {
            column: name.to_string(),
            type_name: type_name.to_string(),
        };
        let raw = row.try_get_raw(index).map_err(|_| undecodable())?;
        let value = if raw.is_null() {
            Value::Null
        } else {
            match type_name {
                "BOOL" => get::<bool>(row, index).map(Value::Bool),
                "INT2" => get::<i16>(row, index).map(Value::from),
                "INT4" => get::<i32>(row, index).map(Value::from),
                "INT8" => get::<i64>(row, index).map(Value::from),
                "FLOAT4" => get::<f32>(row, index).map(|v| float(f64::from(v))),
                "FLOAT8" => get::<f64>(row, index).map(float),
                "TEXT" | "VARCHAR" | "CHAR" | "NAME" | "CITEXT" | "UNKNOWN" => {
                    get::<String>(row, index).map(Value::String)
                }
                "UUID" => get::<uuid::Uuid>(row, index).map(|v| Value::String(v.to_string())),
                "TIMESTAMPTZ" => get::<chrono::DateTime<chrono::Utc>>(row, index)
                    .map(|v| Value::String(v.to_rfc3339())),
                "TIMESTAMP" => {
                    get::<chrono::NaiveDateTime>(row, index).map(|v| naive_timestamp(&v))
                }
                "DATE" => {
                    get::<chrono::NaiveDate>(row, index).map(|v| Value::String(v.to_string()))
                }
                "TIME" => {
                    get::<chrono::NaiveTime>(row, index).map(|v| Value::String(v.to_string()))
                }
                "INTERVAL" => get::<sqlx::postgres::types::PgInterval>(row, index).map(|v| {
                    serde_json::json!({
                        "months": v.months,
                        "days": v.days,
                        "microseconds": v.microseconds,
                    })
                }),
                "JSON" | "JSONB" => get::<Value>(row, index),
                "NUMERIC" => match raw.format() {
                    PgValueFormat::Binary => raw
                        .as_bytes()
                        .ok()
                        .and_then(numeric_text)
                        .ok_or_else(|| not_decoded("numeric")),
                    PgValueFormat::Text => raw
                        .as_str()
                        .map(str::to_string)
                        .map_err(|_| not_decoded("numeric")),
                }
                .map(Value::String),
                "BOOL[]" => array::<bool>(row, index, Value::Bool),
                "INT2[]" => array::<i16>(row, index, Value::from),
                "INT4[]" => array::<i32>(row, index, Value::from),
                "INT8[]" => array::<i64>(row, index, Value::from),
                "FLOAT4[]" => array::<f32>(row, index, |v| float(f64::from(v))),
                "FLOAT8[]" => array::<f64>(row, index, float),
                "TEXT[]" | "VARCHAR[]" | "CHAR[]" | "NAME[]" => {
                    array::<String>(row, index, Value::String)
                }
                "UUID[]" => array::<uuid::Uuid>(row, index, |v| Value::String(v.to_string())),
                "TIMESTAMPTZ[]" => array::<chrono::DateTime<chrono::Utc>>(row, index, |v| {
                    Value::String(v.to_rfc3339())
                }),
                // An enum's wire value is its label in both formats.
                _ if matches!(type_info.kind(), PgTypeKind::Enum(_)) => raw
                    .as_str()
                    .map(|label| Value::String(label.to_string()))
                    .map_err(|_| not_decoded("enum label")),
                _ => {
                    return Err(RowJsonError::UnsupportedType {
                        column: name.to_string(),
                        type_name: type_name.to_string(),
                    })
                }
            }
            .map_err(|_| undecodable())?
        };
        object.insert(name.to_string(), value);
    }
    Ok(object)
}

/// A value the bytes did not hold. Every failure below becomes
/// [`RowJsonError::Undecodable`], which names the column.
fn not_decoded(what: &'static str) -> sqlx::Error {
    sqlx::Error::Decode(what.into())
}

fn get<'r, T>(row: &'r PgRow, index: usize) -> Result<T, sqlx::Error>
where
    T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get::<T, _>(index)
}

/// An array column; a NULL element stays `null` inside the array.
fn array<'r, T>(
    row: &'r PgRow,
    index: usize,
    each: impl Fn(T) -> Value,
) -> Result<Value, sqlx::Error>
where
    Vec<Option<T>>: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    let elements = row.try_get::<Vec<Option<T>>, _>(index)?;
    Ok(Value::Array(
        elements
            .into_iter()
            .map(|element| element.map_or(Value::Null, &each))
            .collect(),
    ))
}

/// A JSON number, or for NaN and the infinities (which JSON has no number
/// for, and `serde_json` would write as `null`) the string Postgres prints.
fn float(value: f64) -> Value {
    match serde_json::Number::from_f64(value) {
        Some(number) => Value::Number(number),
        None if value.is_nan() => Value::String("NaN".to_string()),
        None if value > 0.0 => Value::String("Infinity".to_string()),
        None => Value::String("-Infinity".to_string()),
    }
}

fn naive_timestamp(value: &chrono::NaiveDateTime) -> Value {
    Value::String(value.format("%Y-%m-%dT%H:%M:%S%.f").to_string())
}

const NUMERIC_NEGATIVE: u16 = 0x4000;
const NUMERIC_NAN: u16 = 0xC000;
const NUMERIC_POSITIVE_INFINITY: u16 = 0xD000;
const NUMERIC_NEGATIVE_INFINITY: u16 = 0xF000;

/// The decimal text of a `numeric` in Postgres's binary send format, exactly
/// as `numeric_out` prints it (`get_str_from_var`).
///
/// The format is four 16-bit big-endian header fields — the number of
/// base-10000 digits, the weight of the first digit, the sign, and the
/// display scale — then the digits. `None` when the bytes are not that.
pub(crate) fn numeric_text(bytes: &[u8]) -> Option<String> {
    let field = |i: usize| -> Option<u16> {
        let pair = bytes.get(i * 2..i * 2 + 2)?;
        Some(u16::from_be_bytes([pair[0], pair[1]]))
    };
    let digit_count = usize::from(field(0)?);
    let weight = i32::from(field(1)? as i16);
    let sign = field(2)?;
    let scale = usize::from(field(3)?);
    match sign {
        NUMERIC_NAN => return Some("NaN".to_string()),
        NUMERIC_POSITIVE_INFINITY => return Some("Infinity".to_string()),
        NUMERIC_NEGATIVE_INFINITY => return Some("-Infinity".to_string()),
        0 | NUMERIC_NEGATIVE => {}
        _ => return None,
    }
    if bytes.len() != 8 + digit_count * 2 {
        return None;
    }
    let digit = |position: i32| -> Option<u16> {
        match usize::try_from(position) {
            Ok(i) if i < digit_count => {
                let value = field(4 + i)?;
                (value < 10_000).then_some(value)
            }
            // Before the first stored digit or after the last: a zero group.
            _ => Some(0),
        }
    };

    let mut text = String::new();
    if sign == NUMERIC_NEGATIVE {
        text.push('-');
    }
    if weight < 0 {
        text.push('0');
    } else {
        for position in 0..=weight {
            let group = digit(position)?;
            if position == 0 {
                text.push_str(&group.to_string());
            } else {
                text.push_str(&format!("{group:04}"));
            }
        }
    }
    if scale > 0 {
        text.push('.');
        let mut written = 0;
        let mut position = weight + 1;
        while written < scale {
            let group = format!("{:04}", digit(position)?);
            let take = (scale - written).min(4);
            text.push_str(&group[..take]);
            written += take;
            position += 1;
        }
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric(digits: &[u16], weight: i16, sign: u16, scale: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(digits.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&weight.to_be_bytes());
        bytes.extend_from_slice(&sign.to_be_bytes());
        bytes.extend_from_slice(&scale.to_be_bytes());
        for d in digits {
            bytes.extend_from_slice(&d.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn a_numeric_prints_as_postgres_prints_it() {
        // 12345.6789: digits 1, 2345, 6789 at weight 1.
        assert_eq!(
            numeric_text(&numeric(&[1, 2345, 6789], 1, 0, 4)).as_deref(),
            Some("12345.6789")
        );
        // Zero has no digits; its scale still prints.
        assert_eq!(numeric_text(&numeric(&[], 0, 0, 0)).as_deref(), Some("0"));
        assert_eq!(
            numeric_text(&numeric(&[], 0, 0, 2)).as_deref(),
            Some("0.00")
        );
        // 0.0001 is one digit at weight -1; 0.00000001 one at weight -2.
        assert_eq!(
            numeric_text(&numeric(&[1], -1, 0, 4)).as_deref(),
            Some("0.0001")
        );
        assert_eq!(
            numeric_text(&numeric(&[1], -2, NUMERIC_NEGATIVE, 8)).as_deref(),
            Some("-0.00000001")
        );
        // Trailing zero groups are not stored: 10000 is one digit at weight 1.
        assert_eq!(
            numeric_text(&numeric(&[1], 1, 0, 0)).as_deref(),
            Some("10000")
        );
        // A scale shorter than the stored group truncates it.
        assert_eq!(
            numeric_text(&numeric(&[1, 5000], 0, 0, 1)).as_deref(),
            Some("1.5")
        );
        assert_eq!(
            numeric_text(&numeric(&[], 0, NUMERIC_NAN, 0)).as_deref(),
            Some("NaN")
        );
    }

    #[test]
    fn bytes_that_are_not_a_numeric_are_refused() {
        assert_eq!(numeric_text(&[]), None);
        assert_eq!(
            numeric_text(&[0, 1, 0, 0, 0, 0, 0, 0]),
            None,
            "one digit promised, none sent"
        );
        assert_eq!(
            numeric_text(&numeric(&[10_000], 0, 0, 0)),
            None,
            "a digit past base 10000"
        );
        assert_eq!(
            numeric_text(&numeric(&[1], 0, 0x1234, 0)),
            None,
            "an unknown sign"
        );
    }

    #[test]
    fn a_float_json_cannot_hold_is_named_not_nulled() {
        assert_eq!(float(1.5), serde_json::json!(1.5));
        assert_eq!(float(f64::NAN), serde_json::json!("NaN"));
        assert_eq!(float(f64::INFINITY), serde_json::json!("Infinity"));
        assert_eq!(float(f64::NEG_INFINITY), serde_json::json!("-Infinity"));
    }
}
