// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn build_candidate_paths(
    presented: &[X509Certificate],
    cfg: &TrustConfig,
) -> Result<(Vec<CandidatePath>, bool), TrustError> {
    let leaf = presented.first().ok_or(TrustError::NoValidPath)?;
    let mut root_entries = cfg.trust_roots.iter().enumerate().collect::<Vec<_>>();
    root_entries.sort_by(|left, right| left.1.der.cmp(&right.1.der));
    let mut sorted_intermediates = presented
        .iter()
        .skip(1)
        .filter(|certificate| certificate.der != leaf.der)
        .collect::<Vec<_>>();
    sorted_intermediates.sort_by(|left, right| left.der.cmp(&right.der));
    sorted_intermediates.dedup_by(|left, right| left.der == right.der);

    let mut all_paths = Vec::new();
    let mut limit_reached = false;
    let mut work_steps = 0_usize;
    for (root_index, root) in root_entries {
        let root_index = u16::try_from(root_index).map_err(|_| TrustError::Internal)?;
        let intermediates = sorted_intermediates
            .iter()
            .copied()
            .filter(|certificate| certificate.der != root.der)
            .collect::<Vec<_>>();

        let mut search = PathSearch {
            leaf,
            intermediates,
            root,
            root_index,
            paths: Vec::new(),
            work_steps,
            limit_reached: false,
        };
        // The in-progress path is tracked as indices into `intermediates`
        // after the implicit leaf. Certificates are cloned only when a path
        // completes, so dead-end search steps never copy DER material.
        let mut current = Vec::with_capacity(MAX_X509_CHAIN_CERTIFICATES);
        let mut used = vec![false; search.intermediates.len()];
        search_paths(&mut search, &mut current, &mut used, &cfg.link_policy);
        work_steps = search.work_steps;
        let root_search_limit_reached = search.limit_reached;
        limit_reached |= root_search_limit_reached;
        for path in search.paths {
            if all_paths.len() == MAX_CANDIDATE_PATHS {
                limit_reached = true;
                break;
            }
            all_paths.push(path);
        }
        if all_paths.len() == MAX_CANDIDATE_PATHS {
            break;
        }
        if root_search_limit_reached {
            break;
        }
    }

    Ok((all_paths, limit_reached))
}

fn search_paths(
    search: &mut PathSearch<'_>,
    current: &mut Vec<usize>,
    used: &mut [bool],
    link_policy: &crate::ChainLinkPolicy,
) {
    // Candidate material is attacker-controlled. Counting every recursive
    // state, including dead ends, bounds work even when no path reaches an
    // anchor and therefore no completed-path limit would otherwise apply.
    if search.work_steps == MAX_PATH_SEARCH_STEPS {
        search.limit_reached = true;
        return;
    }
    search.work_steps = match search.work_steps.checked_add(1) {
        Some(value) => value,
        None => {
            search.limit_reached = true;
            return;
        }
    };

    if search.paths.len() == MAX_CANDIDATE_PATHS {
        search.limit_reached = true;
        return;
    }
    let Some(child) = path_tail(search, current) else {
        return;
    };
    // The leaf is always the first element of the in-progress path.
    let Some(current_len) = current.len().checked_add(1) else {
        search.limit_reached = true;
        return;
    };

    if certificates_link(child, search.root, link_policy) {
        let candidate_len = match current_len.checked_add(1) {
            Some(value) => value,
            None => {
                search.limit_reached = true;
                return;
            }
        };
        if candidate_len <= MAX_X509_CHAIN_CERTIFICATES {
            let Some(chain) = materialize_path(search, current, candidate_len) else {
                search.limit_reached = true;
                return;
            };
            search.paths.push(CandidatePath {
                chain,
                trust_root_index: search.root_index,
            });
        }
    }

    if current_len >= MAX_X509_CHAIN_CERTIFICATES.saturating_sub(1) {
        return;
    }

    for index in 0..search.intermediates.len() {
        if used.get(index).copied().unwrap_or(true) {
            continue;
        }
        let Some(candidate) = search.intermediates.get(index).copied() else {
            continue;
        };
        let links_to_current = path_tail(search, current)
            .is_some_and(|current_child| certificates_link(current_child, candidate, link_policy));
        if !links_to_current {
            continue;
        }
        set_used(used, index, true);
        current.push(index);
        search_paths(search, current, used, link_policy);
        current.pop();
        set_used(used, index, false);
        if search.limit_reached {
            return;
        }
    }
}

/// Return the last certificate of the in-progress path.
fn path_tail<'a>(search: &PathSearch<'a>, current: &[usize]) -> Option<&'a X509Certificate> {
    match current.last() {
        Some(index) => search.intermediates.get(*index).copied(),
        None => Some(search.leaf),
    }
}

/// Clone the certificates of one completed leaf-to-root path.
fn materialize_path(
    search: &PathSearch<'_>,
    current: &[usize],
    candidate_len: usize,
) -> Option<X509Chain> {
    let mut certs = Vec::with_capacity(candidate_len);
    certs.push(search.leaf.clone());
    for index in current {
        certs.push(search.intermediates.get(*index).copied()?.clone());
    }
    certs.push(search.root.clone());
    Some(X509Chain { certs })
}

fn set_used(used: &mut [bool], index: usize, value: bool) {
    if let Some(slot) = used.get_mut(index) {
        *slot = value;
    }
}

fn certificates_link(
    child: &X509Certificate,
    issuer: &X509Certificate,
    link_policy: &crate::ChainLinkPolicy,
) -> bool {
    crate::validate_certificate_link(child, issuer, link_policy).is_ok()
}

fn push_failure(failures: &mut Vec<TrustFailureReason>, failure: TrustFailureReason) {
    if !failures.contains(&failure) {
        failures.push(failure);
    }
}
