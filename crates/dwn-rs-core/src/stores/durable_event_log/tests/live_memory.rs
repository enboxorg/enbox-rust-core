//! Memory runner for the backend-neutral live battery.

use super::super::live_suite::{memory_live_pair, run_live_suite};

#[tokio::test]
async fn memory_conforms_to_live_durable_event_log_contract() {
    run_live_suite(memory_live_pair).await;
}
