use super::*;

/// What one commit publishes for one chunk.
#[derive(Debug, Clone)]
pub(super) struct ChunkPlan {
    pub(super) chunk_idx: u64,
    /// Pages carried by this entry; `full_page_mask()` means a whole-chunk base.
    pub(super) page_mask: u64,
}

impl ChunkPlan {
    pub(super) fn is_base(&self) -> bool {
        self.page_mask == format::full_page_mask()
    }

    /// Payload bytes this plan contributes to the pack.
    pub(super) fn len(&self) -> usize {
        self.page_mask.count_ones() as usize * cats_api::chunk::DIRTY_PAGE_SIZE as usize
    }

    /// Byte runs to copy out of the cache, coalescing adjacent dirty pages so a
    /// scattered mask still costs few reads.
    fn runs(&self, payload_offset: usize) -> Vec<CopyRun> {
        let page = cats_api::chunk::DIRTY_PAGE_SIZE as u64;
        let chunk_start = self.chunk_idx * CHUNK_SIZE as u64;
        let mut runs = Vec::new();
        let mut dst = payload_offset;
        let mut page_idx = 0u32;
        while page_idx < cats_api::chunk::PAGES_PER_CHUNK {
            if self.page_mask & (1u64 << page_idx) == 0 {
                page_idx += 1;
                continue;
            }
            let first = page_idx;
            while page_idx < cats_api::chunk::PAGES_PER_CHUNK
                && self.page_mask & (1u64 << page_idx) != 0
            {
                page_idx += 1;
            }
            let len = ((page_idx - first) as u64 * page) as usize;
            runs.push(CopyRun {
                file_offset: chunk_start + first as u64 * page,
                dst_offset: dst,
                len,
            });
            dst += len;
        }
        runs
    }
}

/// One contiguous copy from the cache file into the pack payload.
#[derive(Debug, Clone, Copy)]
struct CopyRun {
    file_offset: u64,
    dst_offset: usize,
    len: usize,
}

/// Decide what each dirty chunk publishes: a delta of its dirty pages, or a
/// fresh full base.
///
/// A base is written when the chunk's delta chain is full, or when the Guest
/// dirtied more than half the chunk — past that point a delta saves little and
/// resetting the chain is worth more than the bytes.
pub(super) fn plan_commit(
    dirty: &[(u64, u64)],
    base_map: &[ChunkRef],
    discarded: &[u64],
) -> Vec<ChunkPlan> {
    let pages_per_chunk = cats_api::chunk::PAGES_PER_CHUNK;
    // A discarded chunk carries no pages: `ChunkPlan::len()` is zero, so it
    // occupies no payload and its pack entry publishes no object. It still has to
    // be in the plan, because the commit is what turns its map entry into a Hole
    // and a pending pack has to be able to replay that.
    discarded
        .iter()
        .map(|&chunk_idx| ChunkPlan {
            chunk_idx,
            page_mask: 0,
        })
        .chain(dirty.iter().map(|&(chunk_idx, mask)| {
            let dense = mask.count_ones() * 2 > pages_per_chunk;
            let chain_full = base_map[chunk_idx as usize].layer_count() >= MAX_DELTA_LAYERS;
            let page_mask = if dense || chain_full {
                format::full_page_mask()
            } else {
                mask
            };
            ChunkPlan {
                chunk_idx,
                page_mask,
            }
        }))
        .collect()
}

/// How many threads to use for one commit's copy/hash work.
///
/// Both are per-chunk independent, and both are a large share of FLUSH latency:
/// measured on aarch64, sha256 runs at ~546 MiB/s per core and accounts for
/// roughly 47% of a commit, while the copy reads the dirty set out of the cache
/// file. The cap keeps a big commit from spawning hundreds of threads.
pub(super) fn commit_workers(units: usize) -> usize {
    const MAX: usize = 8;
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(MAX)
        .min(units)
        .max(1)
}

/// Copy the planned bytes out of the cache into the pack payload.
///
/// Runs inside the exclusive commit barrier, so it is the one thing that must be
/// as short as possible: the destination ranges are disjoint and `read_exact_at`
/// takes `&self`, so the copy parallelizes without any locking.
pub(super) fn copy_planned_pages(
    cache: &File,
    plans: &[ChunkPlan],
    payload: &mut [u8],
) -> Result<()> {
    let mut runs = Vec::with_capacity(plans.len());
    let mut offset = 0usize;
    for plan in plans {
        runs.extend(plan.runs(offset));
        offset += plan.len();
    }
    debug_assert_eq!(offset, payload.len());

    let workers = commit_workers(runs.len());
    if workers == 1 {
        for run in &runs {
            cache.read_exact_at(
                &mut payload[run.dst_offset..run.dst_offset + run.len],
                run.file_offset,
            )?;
        }
        return Ok(());
    }

    // Runs are in increasing destination order, so a contiguous group of runs
    // owns a contiguous span of the payload and each worker can be handed its
    // own `&mut` slice.
    let per_worker = runs.len().div_ceil(workers);
    let mut failure: Option<std::io::Error> = None;
    let mut rest = payload;
    let mut spans: Vec<(&[CopyRun], &mut [u8], usize)> = Vec::new();
    for group in runs.chunks(per_worker) {
        let span_start = group[0].dst_offset;
        let span_end = group[group.len() - 1].dst_offset + group[group.len() - 1].len;
        let (span, tail) = rest.split_at_mut(span_end - span_start);
        rest = tail;
        spans.push((group, span, span_start));
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = spans
            .into_iter()
            .map(|(group, span, span_start)| {
                scope.spawn(move || -> std::io::Result<()> {
                    for run in group {
                        let start = run.dst_offset - span_start;
                        cache.read_exact_at(&mut span[start..start + run.len], run.file_offset)?;
                    }
                    Ok(())
                })
            })
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(Err(error)) if failure.is_none() => failure = Some(error),
                Ok(_) => {}
                Err(_) => {
                    if failure.is_none() {
                        failure = Some(std::io::Error::other("commit copy worker panicked"));
                    }
                }
            }
        }
    });
    match failure {
        Some(error) => Err(error.into()),
        None => Ok(()),
    }
}
