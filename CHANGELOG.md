# Changelog

All notable changes to Dragon Forge X are documented in this file.

## [4.0.1] - 2026-08-31

### Security and reliability

- Enforced the user-supplied URL path as the scan scope for target requests.
- Fixed IPv6 target parsing.
- Rejected invalid values for `-threads`.
- Replaced task-per-goroutine scheduling with a bounded worker pool.
- Capped certificate-transparency subdomain liveness probes at 500 targets.
- Reclassified command-like timing results as inconclusive; reflection no longer reports confirmed RCE.
- Reclassified XML entity-marker reflection; it no longer reports confirmed XXE.
- Corrected the `Access-Control-Allow-Origin: *` with credentials CORS classification.
- Required `--active` for GraphQL POST introspection.

## [4.0.0]

Initial public release.
