//! Read-time `$recordLimit` occupancy projection.
//!
//! Covers `DWN-REC-004`: the visible population, including record-limit
//! winners, is independent of delivery and insertion order. Covers
//! `DWN-REC-005`: retained history and the latest visible projection stay
//! distinct — only current latest writes can occupy slots.
//!
//! Parity source: TypeScript `record-limit-occupancy.ts` with the LevelDB
//! application in `message-store-level.ts`/`index-level.ts`. Stores partition
//! matching latest RecordsWrites by direct-parent group, rank each group by
//! `dateCreated` then `recordId` ascending, and apply `max` before the
//! caller's filters, sort, and pagination. Message CID deliberately does not
//! participate: occupancy belongs to the logical record, not an update.
//!

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::descriptors::{RECORDS, WRITE};
use crate::filters::{Filter, FilterKey, Filters, SubtreeFilter};
use crate::stores::KeyValues;
use crate::Value;

/// Read-time `$recordLimit` occupancy policy for one concrete protocol path.
///
/// `context_id` roots the candidate subtree; omitted for root protocol paths
/// and selections scoped only by direct parent. `parent_id` lists explicitly
/// selected direct-parent groups; `None` spans every group in scope, while an
/// explicitly empty list selects nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordLimitOccupancy {
    pub protocol: String,
    pub protocol_path: String,
    pub context_id: Option<String>,
    pub parent_id: Option<Vec<String>>,
    pub max: u64,
}

/// One rankable candidate: a current latest live write.
pub struct OccupancyCandidate<'a> {
    pub record_id: &'a str,
    pub parent_id: Option<&'a str>,
    pub date_created: &'a str,
}

/// The admitted population: occupant record IDs for membership enforcement
/// and per-group rank cutoffs for in-engine enforcement. Both derive from one
/// grouping and ranking pass, so backends cannot disagree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OccupancySelection {
    pub occupant_ids: BTreeSet<String>,
    pub cutoffs: BTreeMap<Option<String>, String>,
}

/// Builds the candidate filter set: current latest live writes for the policy
/// path, optionally fenced to the candidate subtree. Direct-parent scoping
/// happens in [`select_occupants`], never here.
pub fn occupancy_candidate_filters(policy: &RecordLimitOccupancy) -> Filters {
    let mut map = BTreeMap::new();
    map.insert(
        FilterKey::Index("interface".to_string()),
        Filter::Equal(Value::String(RECORDS.to_string())),
    );
    map.insert(
        FilterKey::Index("method".to_string()),
        Filter::Equal(Value::String(WRITE.to_string())),
    );
    map.insert(
        FilterKey::Index("isLatestBaseState".to_string()),
        Filter::Equal(Value::Bool(true)),
    );
    map.insert(
        FilterKey::Index("protocol".to_string()),
        Filter::Equal(Value::String(policy.protocol.clone())),
    );
    map.insert(
        FilterKey::Index("protocolPath".to_string()),
        Filter::Equal(Value::String(policy.protocol_path.clone())),
    );
    if let Some(context_id) = policy.context_id.as_deref() {
        map.insert(
            FilterKey::Index("contextId".to_string()),
            Filter::Subtree(SubtreeFilter {
                subtree: context_id.to_string(),
            }),
        );
    }
    Filters::from(map)
}

/// Ranking key for one candidate: oldest creation time, then record ID.
/// Tuple order is compiler-derived, so ranking never depends on a separator
/// convention. Message CID deliberately does not participate because
/// occupancy belongs to the logical record, not a particular update.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RankKey {
    date_created: String,
    record_id: String,
}

impl RankKey {
    /// Serializes the key for the SQL boundary, where per-group cutoffs cross
    /// as single bind params. U+0000 sorts before all real content, so the
    /// string order equals the tuple order; the SQL rank expression joins the
    /// same components with `char(0)`.
    fn key(&self) -> String {
        format!("{}\0{}", self.date_created, self.record_id)
    }
}

/// Groups candidates by direct-parent scope (records without a parent form
/// the root group), ranks each group, and admits the first `max` per group.
///
/// `parent_ids`: `None` spans every group in scope; `Some` admits only the
/// listed direct-parent groups, and an empty list admits nothing.
///
/// Fails closed: `max == 0` and non-string rank components are errors, never
/// silent widening. Mirrors the upstream throw-on-corrupt-candidate rule.
pub fn select_occupants(
    candidates: &[OccupancyCandidate<'_>],
    max: u64,
    parent_ids: Option<&BTreeSet<String>>,
) -> Result<OccupancySelection, String> {
    if max == 0 {
        return Err(
            "MessageStoreRecordLimitInvalidMax: record-limit max must be a positive integer"
                .to_string(),
        );
    }
    let mut groups: BTreeMap<Option<String>, Vec<(RankKey, String)>> = BTreeMap::new();
    for candidate in candidates {
        let group = candidate.parent_id.map(str::to_string);
        if let Some(selected) = parent_ids {
            let selected = match group.as_deref() {
                Some(parent) => selected.contains(parent),
                None => false,
            };
            if !selected {
                continue;
            }
        }
        groups.entry(group).or_default().push((
            RankKey {
                date_created: candidate.date_created.to_string(),
                record_id: candidate.record_id.to_string(),
            },
            candidate.record_id.to_string(),
        ));
    }

    let mut selection = OccupancySelection::default();
    let limit = max as usize;
    for (group, mut ranked) in groups {
        ranked.sort();
        ranked.truncate(limit);
        let Some((cutoff, _)) = ranked.last() else {
            continue;
        };
        selection.cutoffs.insert(group, cutoff.key());
        selection
            .occupant_ids
            .extend(ranked.into_iter().map(|(_, record_id)| record_id));
    }
    Ok(selection)
}

/// Extracts rankable candidates from index maps. Rows missing string
/// `recordId`/`dateCreated`, or carrying a non-string `parentId`, are
/// corrupt candidates and fail the whole read rather than widening it.
pub fn occupancy_candidates<'a>(
    indexes: impl Iterator<Item = &'a KeyValues>,
) -> Result<Vec<OccupancyCandidate<'a>>, String> {
    indexes
        .map(|values| {
            let record_id = match values.get("recordId") {
                Some(Value::String(record_id)) => record_id.as_str(),
                _ => {
                    return Err("MessageStoreRecordLimitInvalidCandidate: record-limit candidates require string recordId indexes".to_string());
                }
            };
            let date_created = match values.get("dateCreated") {
                Some(Value::String(date_created)) => date_created.as_str(),
                _ => {
                    return Err("MessageStoreRecordLimitInvalidCandidate: record-limit candidates require string dateCreated indexes".to_string());
                }
            };
            let parent_id = match values.get("parentId") {
                None => None,
                Some(Value::String(parent_id)) => Some(parent_id.as_str()),
                _ => {
                    return Err("MessageStoreRecordLimitInvalidCandidate: record-limit candidate parentId must be a string".to_string());
                }
            };
            Ok(OccupancyCandidate {
                record_id,
                parent_id,
                date_created,
            })
        })
        .collect()
}

/// Returns true when a row's record ID belongs to the admitted occupant set.
/// Rows without a string record ID cannot be occupants.
pub fn is_occupant(indexes: &KeyValues, occupant_ids: &BTreeSet<String>) -> bool {
    matches!(indexes.get("recordId"), Some(Value::String(record_id)) if occupant_ids.contains(record_id))
}

/// Resolves the admitted occupant record IDs over row-based stores (memory
/// and test doubles): tenant plus candidate prefilter, shared selection.
/// Returns `None` when nothing occupies a slot so callers short-circuit.
/// Callers retain `recordId` membership before sorting, paging, or counting,
/// so pagination and counts run over the admitted set through the ordinary
/// path rather than by post-filtering one fetched page.
pub fn occupant_ids_for_rows<'a>(
    rows: impl Iterator<Item = (&'a str, &'a KeyValues)>,
    tenant: &str,
    policy: &RecordLimitOccupancy,
) -> Result<Option<BTreeSet<String>>, String> {
    let candidate_filters = occupancy_candidate_filters(policy);
    let candidates = occupancy_candidates(
        rows.filter(|(row_tenant, _)| *row_tenant == tenant)
            .filter(|(_, indexes)| {
                crate::filters::matching::matches_filters(indexes, Some(&candidate_filters))
            })
            .map(|(_, indexes)| indexes),
    )?;
    let parent_ids = policy
        .parent_id
        .as_ref()
        .map(|ids| ids.iter().cloned().collect::<BTreeSet<_>>());
    let selection = select_occupants(&candidates, policy.max, parent_ids.as_ref())?;
    if selection.occupant_ids.is_empty() {
        return Ok(None);
    }
    Ok(Some(selection.occupant_ids))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate<'a>(
        record_id: &'a str,
        parent_id: Option<&'a str>,
        date_created: &'a str,
    ) -> OccupancyCandidate<'a> {
        OccupancyCandidate {
            record_id,
            parent_id,
            date_created,
        }
    }

    // Covers: DWN-REC-004
    #[test]
    fn selection_admits_oldest_max_per_group() {
        let candidates = [
            candidate("r3", None, "2025-01-03T00:00:00.000000Z"),
            candidate("r1", None, "2025-01-01T00:00:00.000000Z"),
            candidate("r2", None, "2025-01-02T00:00:00.000000Z"),
        ];
        let selection = select_occupants(&candidates, 2, None).expect("selection must succeed");
        assert_eq!(
            selection.occupant_ids,
            BTreeSet::from(["r1".to_string(), "r2".to_string()])
        );
        assert_eq!(selection.cutoffs.len(), 1);
        assert!(selection.cutoffs.contains_key(&None));
    }

    // Covers: DWN-REC-004
    #[test]
    fn selection_partitions_by_direct_parent() {
        let candidates = [
            candidate("a1", Some("pa"), "2025-01-01T00:00:00.000000Z"),
            candidate("a2", Some("pa"), "2025-01-02T00:00:00.000000Z"),
            candidate("a3", Some("pa"), "2025-01-03T00:00:00.000000Z"),
            candidate("b1", Some("pb"), "2025-01-01T00:00:00.000000Z"),
            candidate("root", None, "2020-01-01T00:00:00.000000Z"),
        ];
        let selection = select_occupants(&candidates, 2, None).expect("selection must succeed");
        assert_eq!(
            selection.occupant_ids,
            ["a1", "a2", "b1", "root"]
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<_>>(),
            "each group keeps its own max; the root group is independent"
        );
        assert_eq!(selection.cutoffs.len(), 3);

        let scoped = select_occupants(&candidates, 2, Some(&BTreeSet::from(["pa".to_string()])))
            .expect("selection must succeed");
        assert_eq!(
            scoped.occupant_ids,
            BTreeSet::from(["a1".to_string(), "a2".to_string()]),
            "explicit parent selection spans only listed groups"
        );

        let empty = select_occupants(&candidates, 2, Some(&BTreeSet::new()))
            .expect("selection must succeed");
        assert!(empty.occupant_ids.is_empty());
        assert!(empty.cutoffs.is_empty());
    }

    // Covers: DWN-REC-004
    #[test]
    fn selection_breaks_creation_ties_by_record_id() {
        let candidates = [
            candidate("r-c", None, "2025-01-01T00:00:00.000000Z"),
            candidate("r-a", None, "2025-01-01T00:00:00.000000Z"),
            candidate("r-b", None, "2025-01-01T00:00:00.000000Z"),
        ];
        let selection = select_occupants(&candidates, 2, None).expect("selection must succeed");
        assert_eq!(
            selection.occupant_ids,
            BTreeSet::from(["r-a".to_string(), "r-b".to_string()])
        );
    }

    #[test]
    fn selection_rejects_zero_max() {
        assert!(select_occupants(&[], 0, None).is_err());
    }

    #[test]
    fn candidates_reject_non_string_rank_components() {
        let corrupt = BTreeMap::from([
            ("recordId".to_string(), Value::String("r".to_string())),
            ("dateCreated".to_string(), Value::Number(42)),
        ]);
        assert!(occupancy_candidates([&corrupt].into_iter()).is_err());

        let corrupt_parent = BTreeMap::from([
            ("recordId".to_string(), Value::String("r".to_string())),
            (
                "dateCreated".to_string(),
                Value::String("2025-01-01T00:00:00.000000Z".to_string()),
            ),
            ("parentId".to_string(), Value::Number(7)),
        ]);
        assert!(occupancy_candidates([&corrupt_parent].into_iter()).is_err());
    }

    // Covers: DWN-REC-004
    #[test]
    fn candidate_filter_pins_latest_live_writes_for_policy_path() {
        let policy = RecordLimitOccupancy {
            protocol: "https://example.com/protocol/threads".to_string(),
            protocol_path: "thread/message".to_string(),
            context_id: Some("ctx-a".to_string()),
            parent_id: None,
            max: 2,
        };
        let filters = occupancy_candidate_filters(&policy);
        let matching = BTreeMap::from([
            (
                "interface".to_string(),
                Value::String("Records".to_string()),
            ),
            ("method".to_string(), Value::String("Write".to_string())),
            ("isLatestBaseState".to_string(), Value::Bool(true)),
            (
                "protocol".to_string(),
                Value::String("https://example.com/protocol/threads".to_string()),
            ),
            (
                "protocolPath".to_string(),
                Value::String("thread/message".to_string()),
            ),
            (
                "contextId".to_string(),
                Value::String("ctx-a/child".to_string()),
            ),
        ]);
        assert!(crate::filters::matching::matches_filters(
            &matching,
            Some(&filters)
        ));
    }
}
