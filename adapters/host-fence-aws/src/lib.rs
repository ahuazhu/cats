//! AWS production effects for the provider-neutral HostFence and
//! ObjectWrite Gateway authority boundaries.

mod binding;
mod host_fence;
mod object_write;

pub use binding::{AwsProviderBindingError, VerifiedAwsProviderBinding};
pub use host_fence::{AwsHostFenceConfig, AwsHostFenceProvider, AwsHostTarget};
pub use object_write::{AwsObjectWriteConfig, AwsObjectWriteGatewayDownstream};
