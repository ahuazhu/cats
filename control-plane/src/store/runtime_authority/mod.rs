//! PostgreSQL persistence for the ADR-0042 volume authority core.

mod events;
mod pg_codec;
mod product;
mod product_rows;
mod rows;
mod volume;

#[cfg(test)]
mod product_tests;

#[cfg(test)]
mod tests;
