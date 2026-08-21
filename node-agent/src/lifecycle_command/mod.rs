//! Durable, bounded Node-local state for one atomic lifecycle command per Cat.

pub mod executor;
pub mod installed;
pub mod journal;
pub mod runner;
pub mod strong_stop;
