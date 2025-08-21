# Branching Strategy

- main: protected, release-ready
- develop: integration branch for next release
- feature/*: feature branches from develop
- hotfix/*: urgent fixes from main

Workflow:
1. Branch from `develop` as `feature/MX-TY-short-desc`
2. Commit using conventional commits with task IDs (e.g., `feat(M1-T2): ...`)
3. Open PR into `develop`; squash-merge
4. Periodically release: merge `develop` -> `main` with tag