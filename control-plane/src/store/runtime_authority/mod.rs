//! PostgreSQL persistence for the ADR-0042 volume authority core.

mod events;
mod pg_codec;
mod rows;
mod volume;

#[cfg(test)]
mod tests;
