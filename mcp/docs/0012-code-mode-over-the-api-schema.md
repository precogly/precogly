# 0012: Code mode over the API schema

Status: proposed
Date: 2026-11-01
Relates to: #405, #441, #487

The MCP server exposes three generic tools over Precogly's OpenAPI schema instead of one
tool per question. The schema drf-spectacular generates becomes the only description of
the API anyone maintains.

## Context

Each MCP capability exists because someone wrote a tool for it. There are four. The REST
API has 181 paths and 352 operations (`manage.py spectacular` on `main` at `03af2dd`).
Continuing means hand-writing a second API that always trails the first, and each new
question shape costs another tool.

A planned in-app assistant needs the same capabilities. Two separate surfaces would drift.

## Decision

```text
  agent                       /mcp                             Precogly
    |-- search(code) -------->| code runs over the schema        |
    |<-- matching operations -|   (sandbox, no network)          |
    |-- execute(code) ------->| code calls request() ----------->| /api/... as the
    |<-- capped result -------|<---------------------------------|  resolved user
    |-- whoami() ------------>| user, organizations, scopes      |
```

- **`search`** runs model-written Python over the schema and returns the operations it
  selects. The schema never enters the model's context, and a new viewset is reachable as
  soon as the schema describes it.
- **`execute`** runs model-written Python in the `pydantic-monty` sandbox. Its only
  capability is `request(method, path, params, body)`, which the host performs in-process
  as the resolved user. The bearer token is never forwarded.
- **`whoami`** returns the user, their organizations, and the token's scopes.
- **Unsafe methods require the `write` scope**, checked in `request()`. This covers MCP02
  in #487.
- **Results are capped**, with truncation marked. The size is unset until measured.
- **`request_all(path)` follows pagination**, so reading one page and counting it is
  not the easy path.
- **`execute` returns the code it ran with its result.** The same code on the same data
  gives the same answer, so any answer can be audited and reproduced.
- **The hand-written tools are removed**
  ([0014](0014-tools-call-the-api-in-process.md)). A deterministic shortcut tool or a
  reviewed recipe comes back only for a question that needs one consistent answer, chosen
  by the evaluation below.
- **The in-app assistant calls the same three functions.** This needs
  `ChatProvider.complete()` to accept tool definitions.

## Prerequisites

- **An accurate schema.** `execute` can only call what `search` finds. On `main`,
  `spectacular` reports 151 unique warnings and 7 unique errors.
- **A reviewed schema.** `search` reads the schema live, so a viewset change can alter
  what agents find without anyone seeing it. A committed `backend/openapi.yml` with a CI
  drift check makes every change to the API surface show in a pull request's diff. #666's
  72 missing query parameters are what it would have caught. Its own pull request, since
  it changes every API pull request.
- **A measured consistency baseline.** About 20 questions with known answers on seeded
  data, each run several times, with and without code mode, counting wrong answers and
  disagreements. It decides which questions get a shortcut tool or recipe.
- **Central tenancy enforcement.** `execute` reaches every viewset. #405 is open; this
  waits on #441 step 3, where an unscoped query fails closed.

## Alternatives

- **One tool per endpoint, generated from the schema.** 352 tools, far past the point
  where tool selection degrades.
- **Keep hand-writing tools.** One tool per question shape, and nothing shared with the
  in-app assistant.
- **`execute` calls `ORMReader`.** A second hand-written API. Not safer either: #487
  (MCP10) found its catalog reads unfiltered.
- **Agents call `/api/` with a personal access token.** Excludes clients without a shell,
  puts a broad credential in the agent's environment, and there is no PAT model.

## Trade-offs

- **Security rests on enforcement, not construction.** A tool does only what it was
  written to do; `execute` does whatever the user's REST permissions allow. Hence #441 is a
  prerequisite.
- **The same question can get different answers.** Hand-written tools already left the
  choice of tool, arguments and summary to the model; code mode adds endpoints, filters,
  pagination and arithmetic. The client, not the server, controls sampling, so the server
  can only make wrong programs harder to write (`request_all`, capped results, worked
  examples in the tool descriptions) and answers auditable (returned code). Only a
  deterministic tool guarantees one answer, and only for the question it covers.
- **Small local models write worse code.** The evaluation shows whether they need
  shortcut tools.
- **`pydantic-monty` is experimental.** Pin it.
- **Prompt injection can act.** Tenant-authored text reaches the agent unmarked (#487,
  MCP06). Writes stay behind the scope check, and the in-app assistant returns writes as
  proposals the user accepts.

## Open

- The result cap.
- Whether recipes are tools, or skills served as in `cloudflare/skills`
  (`src/skills/sync.ts` in the Cloudflare server at `e8bc56f`). Relates to the Skills Hub
  discussion, #178.

## References

- Cloudflare MCP server, README at
  [`e8bc56f`](https://github.com/cloudflare/mcp/blob/e8bc56f8638bc8ee6b6a2ccc1541b7fab46187e2/README.md):
  "2500 endpoints in 1k tokens" with code mode, ~244k tokens with one tool per endpoint.
- Anthropic, [Code execution with MCP](https://www.anthropic.com/research/code-execution-with-mcp).
