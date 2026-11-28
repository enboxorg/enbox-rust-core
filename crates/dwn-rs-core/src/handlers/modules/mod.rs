mod common;
pub(crate) mod configure;
pub(crate) mod query;
pub mod repair;
pub(crate) mod upgrade;

pub use configure::{fetch_module_definition, ControlRepairer};

#[cfg(test)]
mod tests;
