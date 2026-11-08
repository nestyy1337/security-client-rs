//! Elasticsearch queries that match what exception items suppress.
//!
//! The clauses are those Kibana's detection engine builds when it applies
//! exceptions to a rule's search, identical in 8.19 and 9.x. Kibana negates the
//! query; these functions return it un-negated, so a search with it finds the
//! documents the exceptions would suppress.
//!
//! Value-list entries need the list's contents and are refused. Expired items
//! are not filtered out; Kibana skips them, so leave them out of [`query`].
//! When an item has `os_types`, Kibana may order the clauses inside a `filter`
//! differently; the order does not change what matches.
use serde::Deserialize as _;
use serde_json::{Value, json};

use super::{Entry, ExceptionItem, NestedEntry, Operator, OsType};
use crate::{Error, Result};

/// The query matching documents that any of `items` would suppress.
///
/// Fails with [`Error::InvalidRequest`] when there are no items, since an empty
/// query would match everything, or when an item has no entries, a value-list
/// entry, or an entry type this client does not model.
pub fn query<'i>(items: impl IntoIterator<Item = &'i ExceptionItem>) -> Result<Value> {
    let mut should = Vec::new();
    for item in items {
        let context = |error: Error| match error {
            Error::InvalidRequest(message) => {
                Error::InvalidRequest(format!("exception item {:?}: {message}", item.item_id))
            }
            other => other,
        };
        let entries = item
            .entries
            .iter()
            .map(Entry::deserialize)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| invalid("an entry has a type this client does not model"))
            .map_err(context)?;
        should.extend(item_clauses(&entries, &item.os_types).map_err(context)?);
    }
    if should.is_empty() {
        return Err(invalid("at least one exception item is required"));
    }
    Ok(json!({"bool": {"should": should}}))
}

/// The query matching documents that one item with these entries and OS types
/// would suppress. Errors are as for [`query`].
pub fn item_query(entries: &[Entry], os_types: &[OsType]) -> Result<Value> {
    Ok(json!({"bool": {"should": item_clauses(entries, os_types)?}}))
}

fn item_clauses(entries: &[Entry], os_types: &[OsType]) -> Result<Vec<Value>> {
    if entries.is_empty() {
        return Err(invalid("an exception item needs at least one entry"));
    }
    let mut clauses = entries.iter().map(entry).collect::<Result<Vec<_>>>()?;
    if os_types.is_empty() {
        let clause = if clauses.len() == 1 {
            clauses.remove(0)
        } else {
            json!({"bool": {"filter": clauses}})
        };
        return Ok(vec![clause]);
    }
    // Endpoint agents report the OS in `host.os.name.caseless`, others in `host.os.type`.
    let mut alternatives = Vec::new();
    for field in ["host.os.type", "host.os.name.caseless"] {
        for os in os_types {
            let mut filter = vec![match_phrase(field, os.as_str(), Operator::Included)];
            filter.extend(clauses.iter().cloned());
            alternatives.push(json!({"bool": {"filter": filter}}));
        }
    }
    Ok(alternatives)
}

fn entry(entry: &Entry) -> Result<Value> {
    match entry {
        Entry::Match {
            field,
            operator,
            value,
        } => Ok(match_phrase(field, value, *operator)),
        Entry::MatchAny {
            field,
            operator,
            value,
        } => match_any(field, value, *operator),
        Entry::Exists { field, operator } => Ok(exists(field, *operator)),
        Entry::Wildcard {
            field,
            operator,
            value,
        } => Ok(negate(
            json!({"bool": {"filter": {"wildcard": {field: value}}}}),
            *operator,
        )),
        Entry::List { .. } => Err(invalid("value-list entries are not supported")),
        Entry::Nested { field, entries } => nested(field, entries),
    }
}

fn nested(path: &str, entries: &[NestedEntry]) -> Result<Value> {
    let mut clauses = entries
        .iter()
        .map(|entry| {
            Ok(match entry {
                NestedEntry::Match {
                    field,
                    operator,
                    value,
                } => match_phrase(&format!("{path}.{field}"), value, *operator),
                NestedEntry::MatchAny {
                    field,
                    operator,
                    value,
                } => match_any(&format!("{path}.{field}"), value, *operator)?,
                NestedEntry::Exists { field, operator } => {
                    exists(&format!("{path}.{field}"), *operator)
                }
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let query = match clauses.len() {
        0 => return Err(invalid("a nested entry needs at least one entry")),
        1 => clauses.remove(0),
        _ => json!({"bool": {"filter": clauses}}),
    };
    Ok(json!({"nested": {"path": path, "query": query, "score_mode": "none"}}))
}

fn match_phrase(field: &str, value: &str, operator: Operator) -> Value {
    negate(
        json!({"bool": {"minimum_should_match": 1, "should": [{"match_phrase": {field: value}}]}}),
        operator,
    )
}

fn match_any(field: &str, values: &[String], operator: Operator) -> Result<Value> {
    let clause = match values {
        [] => return Err(invalid("a match_any entry needs at least one value")),
        [value] => match_phrase(field, value, Operator::Included),
        values => json!({"bool": {
            "minimum_should_match": 1,
            "should": values
                .iter()
                .map(|value| match_phrase(field, value, Operator::Included))
                .collect::<Vec<_>>(),
        }}),
    };
    Ok(negate(clause, operator))
}

fn exists(field: &str, operator: Operator) -> Value {
    negate(
        json!({"bool": {"minimum_should_match": 1, "should": [{"exists": {"field": field}}]}}),
        operator,
    )
}

fn negate(clause: Value, operator: Operator) -> Value {
    match operator {
        Operator::Included => clause,
        Operator::Excluded => json!({"bool": {"must_not": clause}}),
    }
}

fn invalid(message: &str) -> Error {
    Error::InvalidRequest(message.to_owned())
}
