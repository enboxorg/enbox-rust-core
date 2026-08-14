use std::future::Future;

use crate::{
    errors::EventLogError,
    stores::{EventLogReadOptions, EventLogReadResult},
    ProgressToken,
};

// Replication bounds represents the range of available replication feed entries for
// a given tenant. Lower bound is the oldest ProgressToken available, and upper bound
// is the latest ProgressToken available.
pub type ReplicationBounds = (ProgressToken, ProgressToken);

pub trait ReplicationFeedReader: Default {
    // Returns an available feed that matches the given filters
    // after theprovided cursor.
    fn log_read(
        &self,
        tenant: &str,
        options: EventLogReadOptions,
    ) -> impl Future<Output = Result<Vec<EventLogReadResult>, EventLogError>> + Send;

    // Return the oldest, and latest ProgressTokens for a tenant
    fn log_bounds(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<ReplicationBounds, EventLogError>> + Send;

    // Fingerprint returns the replication fingerprint for a given tenant.
    fn fingerprint(
        &self,
        tenant: &str,
        scopes: &[String],
    ) -> impl Future<Output = Result<String, EventLogError>> + Send;

    // Return the current stream epoch
    fn epoch(&self) -> impl Future<Output = Result<u64, EventLogError>> + Send;
}
