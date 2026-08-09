//! PostgreSQL persistence for the ADR-0042 volume authority core.

#[allow(
    dead_code,
    reason = "F2c is the ready-to-wire service boundary consumed by the F2d HTTP cutover"
)]
pub(crate) mod cat_create_service;
mod events;
pub(super) mod pg_codec;
mod product;
mod product_rows;
pub(super) mod rows;
mod volume;

#[cfg(test)]
mod cat_create_service_tests;

#[cfg(test)]
mod product_tests;

#[cfg(test)]
mod tests;
