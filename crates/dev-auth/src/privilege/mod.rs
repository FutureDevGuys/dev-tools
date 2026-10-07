//! Reusable administrative authority, separate from credential admission.
pub mod adapter;
pub mod cli;
pub mod custody;
pub mod deadline;
pub mod launch;
pub mod login;
pub mod platform;
pub mod policy;
pub mod protocol;
pub mod receipt_install;
pub mod runtime;
pub mod sandbox;
#[cfg(test)]
mod tests;
