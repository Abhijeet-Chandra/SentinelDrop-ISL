# Hosted HTTP Monitor Implementation Plan

> **For agentic workers:** Use the test-driven-development and verification-before-completion workflows. This plan is implemented in the current isolated worktree.

**Goal:** Give the deployed Admin dashboard useful live traffic measurements when the Render host cannot provide TShark capture interfaces.

**Architecture:** Keep the existing TShark packet-capture API for capable local hosts. Add a separate, bounded in-memory monitor for completed FastAPI HTTP requests. The Admin UI labels request counts and Content-Length header totals as application measurements, not network packets; it never displays payloads, addresses, credentials, or raw paths.

**Tech Stack:** FastAPI middleware and protected Admin routes, Python standard-library locks and monotonic time, React dashboard.

**Constraints:** One backend instance; 30-second and 1,000-request maximum; ignore health checks and monitor polling; monitor state resets on process restart; no dependency or billing change.

## Steps

- [x] Write failing tests for access control, start/stop/expiry, aggregate counts, privacy, and input limits.
- [x] Implement the in-memory HTTP monitor and FastAPI recording middleware.
- [x] Add Admin-only start/status/stop routes and verify the tests pass.
- [x] Add a clearly labeled hosted request-monitor card; show TShark unavailability as an explanation rather than a generic failure.
- [ ] Run backend tests, frontend lint/build, and a live deployment smoke check.
- [ ] Commit and push only after verification; confirm the new Render and Vercel deployments are ready.
