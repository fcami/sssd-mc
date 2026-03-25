# TODO

- [ ] Fix chain length measurement in analysis.rs — `chain_length()` picks first record's hash1 to follow, but a bucket can contain records chained by different hashes. Should measure reachability per-hash, not per-bucket. `max_chain_length` stat is unreliable.
