//! Shared filter-match engine.
//!
//! Evaluates a [`Filters`] (TypeScript `MessageFilter[]`) against a
//! [`KeyValues`] index map. Used by both the in-memory `EventLog` and the
//! SQLite `MessageStore` so the two cannot drift on prefix / range / set
//! semantics.
//!
//! Behavior:
//!
//! - The outer [`Filters`] is OR-of-AND. A `KeyValues` matches when at
//!   least one filter set has every clause satisfied. An empty filter
//!   list (or `None`) matches everything.
//! - `Filter::Equal` and `Filter::OneOf` compare with [`Value`] equality;
//!   for arrays, any element equality wins.
//! - `Filter::Prefix` requires both actual and expected to be
//!   `Value::String`. Other shapes deliberately do not match: serializing
//!   non-string values (cids, datetimes, numbers) to strings before
//!   comparing leads to surprising matches and the TypeScript implementation
//!   does not do it.
//! - `Filter::Range` evaluates lower and upper bounds via [`compare_values`];
//!   non-comparable variant pairs (e.g. `Number` vs `String`) yield `None`
//!   and therefore do not match.

use std::cmp::Ordering;
use std::ops::Bound;

use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
use crate::stores::KeyValues;
use crate::Value;

/// Returns `true` iff `indexes` satisfies at least one filter set in `filters`.
///
/// `None` filters or an empty filter list both match everything; this matches
/// the TypeScript `MessageFilter[] = []` semantics.
pub fn matches_filters(indexes: &KeyValues, filters: Option<&Filters>) -> bool {
    let Some(filters) = filters else {
        return true;
    };
    let filter_sets = filters.clone().into_iter().collect::<Vec<_>>();
    if filter_sets.is_empty() {
        return true;
    }
    filter_sets.into_iter().any(|filter_set| {
        filter_set.into_iter().all(|(key, filter)| {
            let key = filter_key(&key);
            indexes
                .get(&key)
                .is_some_and(|actual| matches_filter(actual, &filter))
        })
    })
}

fn filter_key(key: &FilterKey) -> String {
    match key {
        FilterKey::Index(key) | FilterKey::Tag(key) => key.clone(),
    }
}

/// Returns `true` iff `actual` satisfies the supplied [`Filter`].
pub fn matches_filter(actual: &Value, filter: &Filter<Value>) -> bool {
    match filter {
        Filter::Equal(expected) => matches_equal(actual, expected),
        Filter::OneOf(expected_values) => expected_values
            .iter()
            .any(|expected| matches_equal(actual, expected)),
        Filter::Prefix(prefix) => match (actual, prefix) {
            (Value::String(actual), Value::String(prefix)) => actual.starts_with(prefix),
            _ => false,
        },
        Filter::Range(range) => matches_range(actual, range),
    }
}

fn matches_equal(actual: &Value, expected: &Value) -> bool {
    match actual {
        Value::Array(values) => values.iter().any(|value| value == expected),
        _ => actual == expected,
    }
}

fn matches_range(actual: &Value, range: &RangeFilter<Value>) -> bool {
    match range {
        RangeFilter::Numeric(lower, upper) | RangeFilter::Criterion(lower, upper) => {
            bound_matches(actual, lower, true) && bound_matches(actual, upper, false)
        }
    }
}

fn bound_matches(actual: &Value, bound: &Bound<Value>, lower: bool) -> bool {
    match bound {
        Bound::Unbounded => true,
        Bound::Included(expected) => compare_values(actual, expected).is_some_and(|ordering| {
            if lower {
                ordering.is_ge()
            } else {
                ordering.is_le()
            }
        }),
        Bound::Excluded(expected) => compare_values(actual, expected).is_some_and(|ordering| {
            if lower {
                ordering.is_gt()
            } else {
                ordering.is_lt()
            }
        }),
    }
}

/// Compare two index values, returning `None` when they are not naturally
/// comparable (e.g. number vs string). Mixed numeric variants
/// (`Value::Number` and `Value::Float`) are coerced to `f64`.
pub fn compare_values(left: &Value, right: &Value) -> Option<Ordering> {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => Some(left.cmp(right)),
        (Value::Float(left), Value::Float(right)) => left.partial_cmp(right),
        (Value::Number(left), Value::Float(right)) => (*left as f64).partial_cmp(right),
        (Value::Float(left), Value::Number(right)) => left.partial_cmp(&(*right as f64)),
        (Value::String(left), Value::String(right)) => Some(left.cmp(right)),
        (Value::DateTime(left), Value::DateTime(right)) => Some(left.cmp(right)),
        (Value::Cid(left), Value::Cid(right)) => Some(left.to_string().cmp(&right.to_string())),
        (Value::Bool(left), Value::Bool(right)) => Some(left.cmp(right)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ops::Bound;

    use super::*;
    use crate::filters::{Filter, FilterKey, Filters, RangeFilter};

    fn indexes(pairs: &[(&str, Value)]) -> KeyValues {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect::<BTreeMap<_, _>>()
    }

    fn filter_set(pairs: Vec<(&str, Filter<Value>)>) -> BTreeMap<FilterKey, Filter<Value>> {
        pairs
            .into_iter()
            .map(|(key, filter)| (FilterKey::Index(key.to_string()), filter))
            .collect::<BTreeMap<_, _>>()
    }

    #[test]
    fn equal_matches_exact_value() {
        let idx = indexes(&[("k", Value::String("v".into()))]);
        let filters: Filters = vec![filter_set(vec![(
            "k",
            Filter::Equal(Value::String("v".into())),
        )])]
        .into();
        assert!(matches_filters(&idx, Some(&filters)));

        let filters_no: Filters = vec![filter_set(vec![(
            "k",
            Filter::Equal(Value::String("other".into())),
        )])]
        .into();
        assert!(!matches_filters(&idx, Some(&filters_no)));
    }

    #[test]
    fn one_of_matches_any_value() {
        let idx = indexes(&[("k", Value::String("b".into()))]);
        let filters: Filters = vec![filter_set(vec![(
            "k",
            Filter::OneOf(vec![Value::String("a".into()), Value::String("b".into())]),
        )])]
        .into();
        assert!(matches_filters(&idx, Some(&filters)));
    }

    #[test]
    fn prefix_only_matches_string_pairs() {
        let idx_string = indexes(&[("k", Value::String("hello world".into()))]);
        let filters: Filters = vec![filter_set(vec![(
            "k",
            Filter::Prefix(Value::String("hello".into())),
        )])]
        .into();
        assert!(matches_filters(&idx_string, Some(&filters)));

        let idx_number = indexes(&[("k", Value::Number(123))]);
        let filters_num: Filters = vec![filter_set(vec![(
            "k",
            Filter::Prefix(Value::String("12".into())),
        )])]
        .into();
        assert!(!matches_filters(&idx_number, Some(&filters_num)));
    }

    #[test]
    fn range_inclusive_includes_endpoints() {
        let idx = indexes(&[("k", Value::Number(5))]);
        let filters: Filters = vec![filter_set(vec![(
            "k",
            Filter::Range(RangeFilter::Numeric(
                Bound::Included(Value::Number(5)),
                Bound::Included(Value::Number(10)),
            )),
        )])]
        .into();
        assert!(matches_filters(&idx, Some(&filters)));
    }

    #[test]
    fn range_excluded_excludes_endpoints() {
        let idx = indexes(&[("k", Value::Number(5))]);
        let filters: Filters = vec![filter_set(vec![(
            "k",
            Filter::Range(RangeFilter::Numeric(
                Bound::Excluded(Value::Number(5)),
                Bound::Included(Value::Number(10)),
            )),
        )])]
        .into();
        assert!(!matches_filters(&idx, Some(&filters)));
    }

    #[test]
    fn array_value_matches_if_any_element_equals() {
        let idx = indexes(&[(
            "k",
            Value::Array(vec![Value::String("a".into()), Value::String("b".into())]),
        )]);
        let filters: Filters = vec![filter_set(vec![(
            "k",
            Filter::Equal(Value::String("b".into())),
        )])]
        .into();
        assert!(matches_filters(&idx, Some(&filters)));
    }

    #[test]
    fn missing_index_does_not_match() {
        let idx = indexes(&[("a", Value::Number(1))]);
        let filters: Filters =
            vec![filter_set(vec![("b", Filter::Equal(Value::Number(1)))])].into();
        assert!(!matches_filters(&idx, Some(&filters)));
    }

    #[test]
    fn empty_filters_match_all() {
        let idx = indexes(&[("a", Value::Number(1))]);
        let filters: Filters = Filters::default();
        assert!(matches_filters(&idx, Some(&filters)));
        assert!(matches_filters(&idx, None));
    }

    #[test]
    fn or_of_ands_matches_at_least_one_set() {
        let idx = indexes(&[("k", Value::Number(2))]);
        let filters: Filters = vec![
            filter_set(vec![("k", Filter::Equal(Value::Number(1)))]),
            filter_set(vec![("k", Filter::Equal(Value::Number(2)))]),
        ]
        .into();
        assert!(matches_filters(&idx, Some(&filters)));
    }

    #[test]
    fn compare_mismatched_variants_returns_none() {
        assert!(compare_values(&Value::Number(1), &Value::String("1".into())).is_none());
    }
}
