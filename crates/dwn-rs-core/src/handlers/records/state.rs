//! Pure latest-state ordering and transition planning for Records messages.
//!
//! This module decides semantic precedence only. Handlers remain responsible for
//! admission, and stores remain responsible for atomically persisting an accepted
//! transition.

use std::cmp::Ordering;

use chrono::{DateTime, Utc};

use crate::descriptors::{messages::record_id, Descriptor, Records};
use crate::Message;

use super::common::message_cid;

/// Current Enbox Records state classes, ordered from least to most dominant.
///
/// This is an Enbox parity rule, not a claim that the DWN draft defines this
/// particular class ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RecordsStateClass {
    Write,
    Delete,
    Prune,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordsStateOrder {
    class: RecordsStateClass,
    message_timestamp: DateTime<Utc>,
    message_cid: String,
    record_id: String,
}

/// The state-relative result for an otherwise admissible Records state message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordsTransitionPlan {
    /// The exact content-addressed operation is already retained.
    Duplicate { message_cid: String },
    /// A retained state message canonically dominates the candidate.
    Superseded {
        message_cid: String,
        winner_cid: String,
    },
    /// The candidate becomes the canonical state winner.
    ///
    /// `outranked_cids` identifies state messages dominated by the candidate.
    /// Later retention planning may keep and reindex a required initial write;
    /// this pure ordering layer does not decide physical retention.
    Apply {
        message_cid: String,
        outranked_cids: Vec<String>,
    },
}

/// Compares two Records state messages using the current Enbox convergence lattice.
///
/// Class precedence is `prune > plain delete > write`. Messages in the same class
/// use `messageTimestamp`, then message CID, as the canonical tie-break.
pub(crate) fn compare_records_state(
    left: &Message<Descriptor>,
    right: &Message<Descriptor>,
) -> Result<Ordering, String> {
    let left = RecordsStateOrder::try_from(left)?;
    let right = RecordsStateOrder::try_from(right)?;
    if left.record_id != right.record_id {
        return Err(format!(
            "RecordsStateRecordIdMismatch: cannot compare record '{}' with '{}'",
            left.record_id, right.record_id
        ));
    }
    Ok(compare_order(&left, &right))
}

/// Plans the state-relative effect of a candidate against retained messages for
/// the same Record. This function performs no I/O and no authorization.
pub(crate) fn plan_records_transition(
    candidate: &Message<Descriptor>,
    retained: &[Message<Descriptor>],
) -> Result<RecordsTransitionPlan, String> {
    let candidate = RecordsStateOrder::try_from(candidate)?;
    let mut retained_states = Vec::with_capacity(retained.len());

    for message in retained {
        let state = RecordsStateOrder::try_from(message)?;
        if state.record_id != candidate.record_id {
            return Err(format!(
                "RecordsStateRecordIdMismatch: candidate record '{}' was planned with retained record '{}'",
                candidate.record_id, state.record_id
            ));
        }
        if state.message_cid == candidate.message_cid {
            return Ok(RecordsTransitionPlan::Duplicate {
                message_cid: candidate.message_cid,
            });
        }
        retained_states.push(state);
    }

    let winner = retained_states
        .iter()
        .max_by(|left, right| compare_order(left, right));
    if let Some(winner) = winner {
        if compare_order(&candidate, winner) != Ordering::Greater {
            return Ok(RecordsTransitionPlan::Superseded {
                message_cid: candidate.message_cid,
                winner_cid: winner.message_cid.clone(),
            });
        }
    }

    let mut outranked_cids = retained_states
        .into_iter()
        .filter(|state| compare_order(state, &candidate) == Ordering::Less)
        .map(|state| state.message_cid)
        .collect::<Vec<_>>();
    outranked_cids.sort();

    Ok(RecordsTransitionPlan::Apply {
        message_cid: candidate.message_cid,
        outranked_cids,
    })
}

fn compare_order(left: &RecordsStateOrder, right: &RecordsStateOrder) -> Ordering {
    left.class
        .cmp(&right.class)
        .then_with(|| left.message_timestamp.cmp(&right.message_timestamp))
        .then_with(|| left.message_cid.cmp(&right.message_cid))
}

impl TryFrom<&Message<Descriptor>> for RecordsStateOrder {
    type Error = String;

    fn try_from(message: &Message<Descriptor>) -> Result<Self, Self::Error> {
        let (class, message_timestamp, state_record_id) = match &message.descriptor {
            Descriptor::Records(records) => match records.as_ref() {
                Records::Write(descriptor) => (
                    RecordsStateClass::Write,
                    descriptor.message_timestamp,
                    record_id(message).ok_or_else(|| {
                        "RecordsStateRecordIdMissing: RecordsWrite recordId is required".to_string()
                    })?,
                ),
                Records::Delete(descriptor) => (
                    if descriptor.prune {
                        RecordsStateClass::Prune
                    } else {
                        RecordsStateClass::Delete
                    },
                    descriptor.message_timestamp,
                    descriptor.record_id.clone(),
                ),
                _ => return Err(
                    "RecordsStateMessageExpected: message must be RecordsWrite or RecordsDelete"
                        .to_string(),
                ),
            },
            _ => {
                return Err(
                    "RecordsStateMessageExpected: message must be RecordsWrite or RecordsDelete"
                        .to_string(),
                )
            }
        };

        Ok(Self {
            class,
            message_timestamp,
            message_cid: message_cid(message)?,
            record_id: state_record_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptors::{DeleteDescriptor, RecordsWriteDescriptor};
    use crate::interfaces::messages::fields::{Fields, WriteFields};

    const RECORD_ID: &str = "record-1";

    fn write(timestamp: &str, marker: &str) -> Message<Descriptor> {
        let mut descriptor = RecordsWriteDescriptor::default();
        descriptor.message_timestamp = timestamp.parse().expect("valid timestamp");
        descriptor.date_created = descriptor.message_timestamp;
        descriptor.data_cid = marker.to_string();

        Message {
            descriptor: Descriptor::Records(Box::new(Records::Write(Box::new(descriptor)))),
            fields: Fields::Write(WriteFields {
                record_id: Some(RECORD_ID.to_string()),
                ..Default::default()
            }),
        }
    }

    fn delete(timestamp: &str, prune: bool) -> Message<Descriptor> {
        Message {
            descriptor: Descriptor::Records(Box::new(Records::Delete(Box::new(
                DeleteDescriptor {
                    message_timestamp: timestamp.parse().expect("valid timestamp"),
                    record_id: RECORD_ID.to_string(),
                    prune,
                },
            )))),
            fields: Fields::Authorization(Default::default()),
        }
    }

    fn cid(message: &Message<Descriptor>) -> String {
        message_cid(message).expect("fixture must have a CID")
    }

    fn converge(messages: &[Message<Descriptor>], permutation: &[usize]) -> String {
        let mut retained = Vec::new();
        for index in permutation {
            let candidate = messages[*index].clone();
            match plan_records_transition(&candidate, &retained).expect("valid transition") {
                RecordsTransitionPlan::Apply { .. } => retained = vec![candidate],
                RecordsTransitionPlan::Duplicate { .. }
                | RecordsTransitionPlan::Superseded { .. } => {}
            }
        }
        cid(retained.first().expect("permutation has a winner"))
    }

    #[test]
    fn delete_dominates_newer_write_in_both_arrival_orders() {
        // Covers: DWN-REC-004
        // Covers: ENBOX-REC-001
        let newer_write = write("2025-01-12T00:00:00Z", "write-12");
        let older_delete = delete("2025-01-11T00:00:00Z", false);
        let messages = [newer_write, older_delete.clone()];

        assert_eq!(converge(&messages, &[0, 1]), cid(&older_delete));
        assert_eq!(converge(&messages, &[1, 0]), cid(&older_delete));
    }

    #[test]
    fn prune_dominates_newer_plain_delete_in_both_arrival_orders() {
        // Covers: DWN-REC-004
        // Covers: ENBOX-REC-001
        let older_prune = delete("2025-01-11T00:00:00Z", true);
        let newer_delete = delete("2025-01-12T00:00:00Z", false);
        let messages = [older_prune.clone(), newer_delete];

        assert_eq!(converge(&messages, &[0, 1]), cid(&older_prune));
        assert_eq!(converge(&messages, &[1, 0]), cid(&older_prune));
    }

    #[test]
    fn all_write_delete_permutations_converge() {
        // Covers: DWN-REC-004
        // Covers: ENBOX-REC-001
        let write_1 = write("2025-01-10T00:00:00Z", "write-1");
        let write_2 = write("2025-01-12T00:00:00Z", "write-2");
        let tombstone = delete("2025-01-11T00:00:00Z", false);
        let messages = [write_1, write_2, tombstone.clone()];
        let permutations = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];

        for permutation in permutations {
            assert_eq!(converge(&messages, &permutation), cid(&tombstone));
        }
    }

    #[test]
    fn same_class_uses_timestamp_then_cid() {
        // Covers: DWN-REC-004
        let older = delete("2025-01-10T00:00:00Z", false);
        let newer = delete("2025-01-11T00:00:00Z", false);
        assert_eq!(
            compare_records_state(&newer, &older).expect("comparable"),
            Ordering::Greater
        );

        let tied_a = write("2025-01-12T00:00:00Z", "a");
        let tied_b = write("2025-01-12T00:00:00Z", "b");
        let expected = cid(&tied_a).max(cid(&tied_b));
        let messages = [tied_a, tied_b];
        assert_eq!(converge(&messages, &[0, 1]), expected);
        assert_eq!(converge(&messages, &[1, 0]), expected);
    }

    #[test]
    fn exact_cid_is_duplicate_without_a_state_change() {
        // Covers: DWN-REC-003
        let message = write("2025-01-12T00:00:00Z", "same");
        assert_eq!(
            plan_records_transition(&message, std::slice::from_ref(&message))
                .expect("valid transition"),
            RecordsTransitionPlan::Duplicate {
                message_cid: cid(&message)
            }
        );
    }

    #[test]
    fn planner_reports_outranked_states_without_deciding_retention() {
        let older_write = write("2025-01-10T00:00:00Z", "old");
        let newer_write = write("2025-01-12T00:00:00Z", "new");
        let expected_cid = cid(&older_write);

        assert_eq!(
            plan_records_transition(&newer_write, &[older_write]).expect("valid transition"),
            RecordsTransitionPlan::Apply {
                message_cid: cid(&newer_write),
                outranked_cids: vec![expected_cid],
            }
        );
    }
}
