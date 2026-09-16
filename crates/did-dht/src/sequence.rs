use std::time::SystemTime;

use super::error::DhtPublishError;

/// Next BEP44 sequence for a publication: the ceiling of `now` in Unix
/// seconds, monotonically raised past `previous` when given.
///
/// Pure: no clock reads, no I/O. Initial publication passes `None`;
/// recovery passes the resolved `versionId` so a republished document always
/// supersedes it, even on clock rollback.
pub fn next_sequence(now: SystemTime, previous: Option<u64>) -> Result<u64, DhtPublishError> {
    let elapsed = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DhtPublishError::TimeBeforeEpoch)?;
    let now_ceil = elapsed
        .as_secs()
        .checked_add(u64::from(elapsed.subsec_nanos() > 0));
    let now_ceil = now_ceil.ok_or(DhtPublishError::SequenceOverflow)?;

    match previous {
        None => Ok(now_ceil),
        Some(previous) => {
            let bumped = previous
                .checked_add(1)
                .ok_or(DhtPublishError::SequenceOverflow)?;
            Ok(now_ceil.max(bumped))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn at(secs: u64, nanos: u32) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::new(secs, nanos)
    }

    #[test]
    // Covers: DID-DHT-004
    fn initial_sequences_ceil_now() {
        assert_eq!(next_sequence(at(1_700_000_000, 0), None), Ok(1_700_000_000));
        assert_eq!(next_sequence(at(1_700_000_000, 1), None), Ok(1_700_000_001));
        assert_eq!(
            next_sequence(at(1_700_000_000, 999_999_999), None),
            Ok(1_700_000_001)
        );
        assert_eq!(next_sequence(SystemTime::UNIX_EPOCH, None), Ok(0));
    }

    #[test]
    // Covers: DID-DHT-004
    fn previous_sequence_wins_when_newer() {
        // Equal previous still advances: exact retry reuses bytes, a changed
        // publication must supersede.
        assert_eq!(next_sequence(at(100, 0), Some(100)), Ok(101));
        // Clock rollback never moves the sequence backwards.
        assert_eq!(
            next_sequence(at(100, 0), Some(1_700_000_000)),
            Ok(1_700_000_001)
        );
        // Older previous loses to now.
        assert_eq!(
            next_sequence(at(1_700_000_000, 0), Some(42)),
            Ok(1_700_000_000)
        );
        assert_eq!(
            next_sequence(at(1_700_000_000, 1), Some(1_700_000_000)),
            Ok(1_700_000_001)
        );
    }

    #[test]
    fn rejects_pre_epoch_time() {
        let before_epoch = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(
            next_sequence(before_epoch, None),
            Err(DhtPublishError::TimeBeforeEpoch)
        );
        assert_eq!(
            next_sequence(before_epoch, Some(42)),
            Err(DhtPublishError::TimeBeforeEpoch)
        );
    }

    #[test]
    fn rejects_overflow() {
        assert_eq!(
            next_sequence(at(1_700_000_000, 0), Some(u64::MAX)),
            Err(DhtPublishError::SequenceOverflow)
        );
    }
}
