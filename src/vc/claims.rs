//! Merging registered JWT claims into the object of a `vc` or `vp` claim (VCDM 1.1 §6.3.1
//! "JWT Decoding"), and the reverse.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use super::{CredentialError, JwtClaims};

/// The object of the claim `name`, cloned.
pub(super) fn claim_object(
    claims: &JwtClaims,
    name: &'static str,
) -> Result<Map<String, Value>, CredentialError> {
    match claims.additional.get(name) {
        Some(Value::Object(object)) => Ok(object.clone()),
        Some(_) => Err(CredentialError::InvalidClaim {
            claim: name,
            reason: "not a JSON object".to_owned(),
        }),
        None => Err(CredentialError::MissingClaim(name)),
    }
}

/// The identifier a property value names: the string itself, or the `id` of an object.
pub(super) fn id_of(value: &Value) -> Option<&str> {
    match value {
        Value::String(id) => Some(id),
        Value::Object(object) => object.get("id").and_then(Value::as_str),
        _ => None,
    }
}

/// Sets `property` of `object` from the string `claim`, or checks they agree when both are
/// present. An object-valued property (an issuer with a name) agrees when its `id` does.
pub(super) fn merge_id(
    object: &mut Map<String, Value>,
    property: &'static str,
    claim: &'static str,
    value: Option<&str>,
) -> Result<(), CredentialError> {
    let Some(value) = value else {
        return Ok(());
    };
    match object.get(property) {
        Some(existing) if id_of(existing) == Some(value) => Ok(()),
        Some(_) => Err(CredentialError::ClaimMismatch { claim, property }),
        None => {
            object.insert(property.to_owned(), Value::String(value.to_owned()));
            Ok(())
        }
    }
}

/// Sets the timestamp `property` of `object` from the `NumericDate` `claim`, or checks they
/// name the same instant when both are present.
pub(super) fn merge_time(
    object: &mut Map<String, Value>,
    property: &'static str,
    claim: &'static str,
    value: Option<i64>,
) -> Result<(), CredentialError> {
    let Some(value) = value else {
        return Ok(());
    };
    let time = JwtClaims::timestamp(value).ok_or_else(|| CredentialError::InvalidClaim {
        claim,
        reason: format!("{value} is out of range"),
    })?;
    match object.get(property) {
        Some(existing) if parse_time(existing) == Some(time) => Ok(()),
        Some(_) => Err(CredentialError::ClaimMismatch { claim, property }),
        None => {
            object.insert(property.to_owned(), Value::String(time.to_rfc3339()));
            Ok(())
        }
    }
}

/// The instant an RFC 3339 string names.
fn parse_time(value: &Value) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.as_str()?)
        .ok()
        .map(|time| time.with_timezone(&Utc))
}

/// Sets the `id` of the one `credentialSubject` of `object` from `sub`, or checks they agree.
pub(super) fn merge_subject(
    object: &mut Map<String, Value>,
    sub: Option<&str>,
) -> Result<(), CredentialError> {
    let Some(sub) = sub else {
        return Ok(());
    };
    let subject = match object.get_mut("credentialSubject") {
        Some(Value::Object(subject)) => subject,
        Some(Value::Array(subjects)) if subjects.len() == 1 => match subjects.first_mut() {
            Some(Value::Object(subject)) => subject,
            _ => return invalid_sub("`credentialSubject` is not an object"),
        },
        Some(Value::Array(subjects)) => {
            return invalid_sub(&format!("the credential has {} subjects", subjects.len()));
        }
        Some(_) => return invalid_sub("`credentialSubject` is not an object"),
        None => {
            object.insert(
                "credentialSubject".to_owned(),
                Value::Object(Map::from_iter([(
                    "id".to_owned(),
                    Value::String(sub.to_owned()),
                )])),
            );
            return Ok(());
        }
    };
    merge_id(subject, "id", "sub", Some(sub)).map_err(|_| CredentialError::ClaimMismatch {
        claim: "sub",
        property: "credentialSubject.id",
    })
}

fn invalid_sub(reason: &str) -> Result<(), CredentialError> {
    Err(CredentialError::InvalidClaim {
        claim: "sub",
        reason: reason.to_owned(),
    })
}

/// Removes `property` from `object` and returns the identifier it named, if it was a string.
/// An object-valued property stays, as the claim cannot carry its other members.
pub(super) fn take_id(object: &mut Map<String, Value>, property: &str) -> Option<String> {
    match object.get(property) {
        Some(Value::String(_)) => object.shift_remove(property).and_then(|value| match value {
            Value::String(id) => Some(id),
            _ => None,
        }),
        Some(other) => id_of(other).map(str::to_owned),
        None => None,
    }
}

/// Removes the `id` of the one `credentialSubject` of `object` and returns it.
pub(super) fn take_subject(
    object: &mut Map<String, Value>,
) -> Result<Option<String>, CredentialError> {
    let subject = match object.get_mut("credentialSubject") {
        Some(Value::Object(subject)) => subject,
        Some(Value::Array(subjects)) if subjects.len() == 1 => match subjects.first_mut() {
            Some(Value::Object(subject)) => subject,
            _ => return Ok(None),
        },
        Some(Value::Array(subjects)) => {
            return Err(CredentialError::MultipleSubjects(subjects.len()));
        }
        _ => return Ok(None),
    };
    Ok(take_id(subject, "id"))
}

/// The JSON object `value` serializes to.
pub(super) fn to_object<T: serde::Serialize>(value: &T) -> Map<String, Value> {
    match serde_json::to_value(value).expect("the data model serializes") {
        Value::Object(object) => object,
        _ => unreachable!("the data model serializes to an object"),
    }
}
