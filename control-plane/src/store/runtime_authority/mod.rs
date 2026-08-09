//! PostgreSQL persistence for the ADR-0042 volume authority core.

mod events;
pub(super) mod pg_codec;
mod product;
mod product_rows;
pub(super) mod rows;
mod volume;

#[cfg(test)]
mod product_tests;

#[cfg(test)]
mod tests;
