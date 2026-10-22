# Security

This is a pre-1.0 verifiable-delivery component, not a certified security product. Report vulnerabilities through the hosting platform's private security advisory channel rather than a public issue.

Known boundaries: hashes_only content mode does not review file content; K3 emergency recovery is not implemented; unanchored tail rollback is undetectable by design; crash/disk-full/cross-host replication are not covered by the current export lock.
