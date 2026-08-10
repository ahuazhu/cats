//! Platform-independent bounds for signed Guest block frontends.

/// One worker thread per queue, and the Linux queue-to-thread map is a 64-bit
/// mask. The bound is wire-visible even when the Node command is built on a
/// non-Linux development host.
pub const MAX_AUTHORIZED_VHOST_QUEUES: usize = 64;
pub const MIN_AUTHORIZED_VHOST_QUEUE_SIZE: u16 = 2;
pub const MAX_AUTHORIZED_VHOST_QUEUE_SIZE: u16 = 32_768;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizedVhostShapeError {
    #[error(
        "authorized vhost-user needs between 1 and {MAX_AUTHORIZED_VHOST_QUEUES} queues, got {0}"
    )]
    QueueCount(usize),
    #[error(
        "authorized vhost-user queue size must be a power of two in {MIN_AUTHORIZED_VHOST_QUEUE_SIZE}..={MAX_AUTHORIZED_VHOST_QUEUE_SIZE}, got {0}"
    )]
    QueueSize(u16),
}

/// Validate the closed vhost-user shape carried by a checkpointed
/// `PrepareDevice` attempt. Both Node command construction and blockd mode
/// admission call this before any engine or listener effect.
pub fn validate_authorized_vhost_shape(
    queues: usize,
    queue_size: u16,
) -> Result<(), AuthorizedVhostShapeError> {
    if queues == 0 || queues > MAX_AUTHORIZED_VHOST_QUEUES {
        return Err(AuthorizedVhostShapeError::QueueCount(queues));
    }
    if !(MIN_AUTHORIZED_VHOST_QUEUE_SIZE..=MAX_AUTHORIZED_VHOST_QUEUE_SIZE).contains(&queue_size)
        || !queue_size.is_power_of_two()
    {
        return Err(AuthorizedVhostShapeError::QueueSize(queue_size));
    }
    Ok(())
}
