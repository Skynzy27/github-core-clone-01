# forge — a GitHub-compatible git forge

A standalone git forge in a single TypeScript file (`main.ts`, Node 22,
standard library only, no git binary, no network beyond the suite). Built for
the make.fun bounty **github-core-clone-01** ("Build a GitHub-compatible git
forge").

## What it serves

- **git smart HTTP** — upload-pack protocol v2 (`ls-refs`, `fetch`, shallow
  clones, deepen, incremental fetch) and receive-pack v0 (fast-forward only,
  per-ref `ok`/`ng` sideband reports). Packfiles are written plain (no
  deltas) and read with full delta resolution (OFS_DELTA and REF_DELTA).
- **REST v3** under `/api/v3` — repositories, branches, commits, contents
  (create/update/delete with stale-sha 409), labels, issues, pull requests
  and squash merges with conflict detection (405).
- **GraphQL v4** at `/api/graphql` — viewer, repository, issues (cursor
  pagination, `orderBy`, `states`), pull requests, `node(id:)`, mutations
  (`createIssue`, `closeIssue`, `createPullRequest`, `mergePullRequest`,
  `addComment`), introspection for `Issue` / `PullRequest` / `Repository` /
  `SearchType`, and batched operations.
- **MCP** at `/mcp` — JSON-RPC 2.0 Streamable HTTP, revision `2026-07-28`
  (`server/discover`) with the legacy `initialize` handshake, six tools
  (`create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request`) acting on the same store as
  REST.

## Running it

```sh
MAKEFUN_SHOP_TOKEN=<token> node main.ts
```

The program binds an ephemeral port (port 0), POSTs `{"port": N}` to
`$MAKEFUN_ENV_URL/register`, then long-polls `$MAKEFUN_ENV_URL/done` and
exits 0 when the suite is done. With no `MAKEFUN_ENV_URL` set it just serves
until killed (handy for local testing).

## Design notes

- **In-memory store.** Repositories, objects, issues and pull requests live
  in Maps; fetch responses are cached per repo (keyed by wants/haves/shallow/
  depth) and invalidated on any ref change, which is what makes the 50-way
  concurrent clone workload fast.
- **Determinism.** Every timestamp the forge emits comes from
  `MAKEFUN_TRIAL_NOW` (REST) or a fixed commit epoch (git objects); there is
  no `Date.now()`, no `Math.random()`, no random UUID anywhere, so a live run
  and its replay leave identical state.
- **Auth.** Every API call needs `Authorization: Bearer <MAKEFUN_SHOP_TOKEN>`
  (except `/healthz`, `GET /api/v3/` and `GET /api/v3/meta`); a missing or
  wrong token is 401, and a repository under any owner other than the token's
  login is 404, never 403.

## Local grade

```sh
node --experimental-strip-types sdk/run.ts --url http://127.0.0.1:<port> --token <token> --perf --json
```

Latest local grade (fresh server, sealed suite): **120/120 checks —
feature 600, agent 200, perf 194, score 994, working 1**.
