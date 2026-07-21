# Releasing

Release publication is a maintainer-only operation. Prepare and review changes without moving existing tags.

Before a release, run the checks in [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md), inspect archive contents and checksums, confirm version metadata, and review the complete diff. GoReleaser snapshots are local verification artifacts and must not publish a GitHub Release.

Existing tags, especially v0.1.0, are immutable. Correct a released problem with a new version rather than rewriting a tag or artifact.
