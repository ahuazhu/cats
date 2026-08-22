//! Typed conversion between runtime authority integers and PostgreSQL BIGINT.
//!
//! PostgreSQL has a signed 64-bit integer while the wire contract uses
//! bounded `u64` newtypes. Callers name the semantic type at the conversion
//! site; there is no raw `u64 -> i64` persistence helper that could silently
//! apply the wrong zero rule.

use std::fmt;

use cats_api::runtime_reconciliation::{
    Epoch, FenceEpoch, Generation, Revision, Sequence, UnixMillis,
};

#[allow(
    dead_code,
    reason = "retained strict disk codecs await the semantic storage adapter"
)]
const POSTGRES_BIGINT_MAX: u64 = i64::MAX.unsigned_abs();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::store) enum PgIntegerError {
    Negative {
        semantic_type: &'static str,
        value: i64,
    },
    Zero {
        semantic_type: &'static str,
    },
    AboveMaximum {
        semantic_type: &'static str,
        value: u64,
    },
}

impl fmt::Display for PgIntegerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Negative {
                semantic_type,
                value,
            } => write!(formatter, "stored {semantic_type} is negative ({value})"),
            Self::Zero { semantic_type } => {
                write!(formatter, "stored {semantic_type} must be positive")
            }
            Self::AboveMaximum {
                semantic_type,
                value,
            } => write!(
                formatter,
                "{semantic_type} value {value} exceeds PostgreSQL BIGINT"
            ),
        }
    }
}

impl std::error::Error for PgIntegerError {}

pub(in crate::store) trait PgBigInt: Copy + Sized {
    const SEMANTIC_TYPE: &'static str;
    const MINIMUM: u64;

    fn get(self) -> u64;
    fn from_validated(value: u64) -> Option<Self>;

    fn to_pg(self) -> Result<i64, PgIntegerError> {
        let value = self.get();
        if value < Self::MINIMUM {
            return Err(PgIntegerError::Zero {
                semantic_type: Self::SEMANTIC_TYPE,
            });
        }
        i64::try_from(value).map_err(|_| PgIntegerError::AboveMaximum {
            semantic_type: Self::SEMANTIC_TYPE,
            value,
        })
    }

    fn from_pg(value: i64) -> Result<Self, PgIntegerError> {
        let value = u64::try_from(value).map_err(|_| PgIntegerError::Negative {
            semantic_type: Self::SEMANTIC_TYPE,
            value,
        })?;
        if value < Self::MINIMUM {
            return Err(PgIntegerError::Zero {
                semantic_type: Self::SEMANTIC_TYPE,
            });
        }
        Self::from_validated(value).ok_or(PgIntegerError::AboveMaximum {
            semantic_type: Self::SEMANTIC_TYPE,
            value,
        })
    }
}

macro_rules! contract_integer {
    ($type:ty, $name:literal, $minimum:literal) => {
        impl PgBigInt for $type {
            const SEMANTIC_TYPE: &'static str = $name;
            const MINIMUM: u64 = $minimum;

            fn get(self) -> u64 {
                self.get()
            }

            fn from_validated(value: u64) -> Option<Self> {
                Self::new(value)
            }
        }
    };
}

contract_integer!(Revision, "Revision", 1);
contract_integer!(Epoch, "Epoch", 1);
contract_integer!(Sequence, "Sequence", 1);
contract_integer!(Generation, "Generation", 0);
contract_integer!(FenceEpoch, "FenceEpoch", 0);
contract_integer!(UnixMillis, "UnixMillis", 0);

macro_rules! positive_integer {
    ($name:ident, $semantic_type:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[allow(
            dead_code,
            reason = "retained strict disk codecs await the semantic storage adapter"
        )]
        pub(super) struct $name(u64);

        #[allow(
            dead_code,
            reason = "retained strict disk codecs await the semantic storage adapter"
        )]
        impl $name {
            pub(super) fn new(value: u64) -> Result<Self, PgIntegerError> {
                if value == 0 {
                    return Err(PgIntegerError::Zero {
                        semantic_type: $semantic_type,
                    });
                }
                if value > POSTGRES_BIGINT_MAX {
                    return Err(PgIntegerError::AboveMaximum {
                        semantic_type: $semantic_type,
                        value,
                    });
                }
                Ok(Self(value))
            }
        }

        impl PgBigInt for $name {
            const SEMANTIC_TYPE: &'static str = $semantic_type;
            const MINIMUM: u64 = 1;

            fn get(self) -> u64 {
                self.0
            }

            fn from_validated(value: u64) -> Option<Self> {
                (value <= POSTGRES_BIGINT_MAX).then_some(Self(value))
            }
        }
    };
}

positive_integer!(SizeBytes, "size_bytes");
positive_integer!(LeaseDurationMs, "lease_duration_ms");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_contract_integer_uses_its_own_zero_rule() {
        assert!(Revision::from_pg(0).is_err());
        assert!(Epoch::from_pg(0).is_err());
        assert!(Sequence::from_pg(0).is_err());
        assert_eq!(Generation::from_pg(0).unwrap().get(), 0);
        assert_eq!(FenceEpoch::from_pg(0).unwrap().get(), 0);
        assert_eq!(UnixMillis::from_pg(0).unwrap().get(), 0);
        assert!(SizeBytes::from_pg(0).is_err());
        assert!(LeaseDurationMs::from_pg(0).is_err());
    }

    #[test]
    fn negative_and_above_bigint_values_never_convert() {
        assert!(matches!(
            FenceEpoch::from_pg(-1),
            Err(PgIntegerError::Negative { .. })
        ));
        assert!(matches!(
            SizeBytes::new(POSTGRES_BIGINT_MAX + 1),
            Err(PgIntegerError::AboveMaximum { .. })
        ));
        assert!(matches!(
            LeaseDurationMs::new(POSTGRES_BIGINT_MAX + 1),
            Err(PgIntegerError::AboveMaximum { .. })
        ));
    }

    #[test]
    fn all_typed_boundaries_accept_the_bigint_maximum() {
        assert_eq!(
            Revision::new(POSTGRES_BIGINT_MAX).unwrap().to_pg(),
            Ok(i64::MAX)
        );
        assert_eq!(
            Epoch::new(POSTGRES_BIGINT_MAX).unwrap().to_pg(),
            Ok(i64::MAX)
        );
        assert_eq!(
            Sequence::new(POSTGRES_BIGINT_MAX).unwrap().to_pg(),
            Ok(i64::MAX)
        );
        assert_eq!(
            Generation::new(POSTGRES_BIGINT_MAX).unwrap().to_pg(),
            Ok(i64::MAX)
        );
        assert_eq!(
            FenceEpoch::new(POSTGRES_BIGINT_MAX).unwrap().to_pg(),
            Ok(i64::MAX)
        );
        assert_eq!(
            UnixMillis::new(POSTGRES_BIGINT_MAX).unwrap().to_pg(),
            Ok(i64::MAX)
        );
        assert_eq!(
            SizeBytes::new(POSTGRES_BIGINT_MAX).unwrap().to_pg(),
            Ok(i64::MAX)
        );
        assert_eq!(
            LeaseDurationMs::new(POSTGRES_BIGINT_MAX).unwrap().to_pg(),
            Ok(i64::MAX)
        );
    }
}
