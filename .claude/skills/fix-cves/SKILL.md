---
name: fix-cves
description: >-
    Find, triage and fix CVEs in the axoidp image and Go module: scan the latest
    released image with Trivy, check reachability with govulncheck, bump the Go
    toolchain or modules (or migrate a module to a new major), verify with a
    rescan, and stop at local commits. Use when asked to "fix CVEs", act on
    "trivy findings" or "govulncheck" output, "bump Go for a security release",
    or do a "routine dependency security update". Not for feature-driven
    dependency upgrades with no CVE behind them.
---

# Fix CVEs

Trivy on the image is the gate; govulncheck is the reachability evidence. CI
(`image-build.yaml`) runs Trivy but never fails on findings and keeps the SARIF
artifact for 5 days only, so scan locally instead of hunting old CI runs.

Set `S=<scratch dir>` for scan output. Never `git push`; stop after local commits.

## 1. Preflight

```sh
git fetch origin
git rev-list --count main..origin/main      # >0: warn, update main first
git switch -c fix/cve-<topic> origin/main
gh pr list --state open --json number,title,headRefName,files \
    --jq '.[] | select(any(.files[].path; test("^(go\\.mod|go\\.sum|\\.go-version|Dockerfile)$")))
        | "\(.number)\t\(.headRefName)\t\(.title)"'
```

- An open PR already doing the bump: continue that PR, don't open a parallel one.
- Note open PRs that add call sites of an API you will migrate: they need a rebase.

## 2. Scan the latest release

`latest` on ghcr tracks `main`; scan the release tag.

```sh
TAG=$(gh release list -L1 --json tagName -q '.[0].tagName')
trivy version --format json | jq -r .VulnerabilityDB.UpdatedAt   # record the DB date
trivy image -q --skip-version-check --scanners vuln --format json \
    ghcr.io/axoflow/axoflow-idp:$TAG > $S/release.json; echo "exit=$?"
jq -e .Results $S/release.json >/dev/null || echo "SCAN FAILED"
jq -r '.Results[] | .Target as $t | .Vulnerabilities[]? |
    [$t, .PkgName, .InstalledVersion, (.FixedVersion // "-"), .Severity, .VulnerabilityID] | @tsv' \
    $S/release.json | sort -u
```

- Redirect stdout; `trivy -o <path>` can fail to write into a sandboxed temp dir.
- Non-zero exit or missing `.Results` means the scan failed. It never means "clean".

## 3. Reachability

```sh
GOTOOLCHAIN=local go run golang.org/x/vuln/cmd/govulncheck@latest -format json ./... > $S/govuln.json
```

`go run` it: a goenv shim may lack a `govulncheck` binary for the pinned Go.
Classify each finding as **called** (a `trace` frame has a `function`),
**imported**, or **required**. govulncheck may lag GHSA: a Trivy finding
missing from govulncheck still counts.

## 4. Triage

One row per package:

| pkg | installed → target | severity | CVE IDs | reachable? |
|-----|--------------------|----------|---------|------------|

Choose the fix per row:

| Case | Fix |
|------|-----|
| `stdlib` | Lowest patch of the current Go minor that fixes all (`curl -s 'https://go.dev/dl/?mode=json'`). See Go pins below. |
| Module, FixedVersion set | `go get <mod>@<lowest fixed, same minor preferred> && go mod tidy`; read `git diff go.mod` for transitive bumps. |
| Module, FixedVersion empty | `gh api "/advisories?cve_id=<CVE>" --jq '.[].vulnerabilities[]'`: the fix may exist only on a newer major module path (go-jose v3 had none, v4.1.6+ did). Plan a major migration; flag it as a code change. |
| No fix anywhere | Report with reachability and ask the user. Don't invent an ignore mechanism (there is no `.trivyignore`). |

- HIGH/CRITICAL: always fix. MEDIUM/LOW: take them when the same or a cheap bump clears them.
- Advisories with only a pseudo-version fix on a package that is not imported
    (e.g. "unmaintained package" notices): report, don't act.

### Go pins (move together, one commit)

| File | Pin |
|------|-----|
| `.go-version` | `X.Y.Z` (CI reads it via setup-go `go-version-file`) |
| `go.mod` | `go X.Y.Z` |
| `Dockerfile` | `FROM --platform=$BUILDPLATFORM golang:X.Y.Z-alpine<A>@sha256:<digest>` |

```sh
docker buildx imagetools inspect golang:X.Y.Z-alpine<A> --format '{{json .Manifest.Digest}}'
goenv install X.Y.Z     # local toolchain before running the gates
```

If the alpine variant is gone for the new patch, move to the next one; the
builder only emits a static `CGO_ENABLED=0` binary into distroless.

## 5. Confirm

Present the triage table and the exact planned commits (subject + files). Wait
for the user's confirmation before editing anything.

## 6. Apply

One commit per package; the Go toolchain is one commit.

| After | Run |
|-------|-----|
| every commit | `just verify` |
| any code change (migration, API fix) | also `just test-race` and `just test-e2e` |

- Lint deprecations from a bump or migration are fixed forward to the new API,
    never `//nolint`. Example: go-jose v4 deprecates `ParseSigned`; tokens are
    compact RS256 JWS, so use
    `jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})`.
- Subjects (match `git log -- go.mod`):
    - `chore: update to Go X.Y.Z for stdlib CVE fixes`
    - `chore(deps): bump <mod> to vX to fix CVE-…`
    - `fix(deps): move to <mod>/vN vX to fix CVE-…` (major migration, code change)
- Body: what the scan flagged, an aligned block, and whether it is reachable
    (name the entry point if called), plus any transitive bumps from `go mod tidy`:

    ```text
    CVE-YYYY-NNNNN  HIGH    crypto/x509  fixed in X.Y.Z
    CVE-YYYY-NNNNN  MEDIUM  net/http     fixed in X.Y.Z
    ```

- End with the Co-Authored-By attribution line, as the existing commits do.

## 7. Verify

```sh
just image                                          # ghcr.io/axoflow/axoflow-idp:latest, local
for i in 1 2; do
    trivy image -q --skip-version-check --scanners vuln --format json \
        ghcr.io/axoflow/axoflow-idp:latest > $S/local$i.json || echo "SCAN $i FAILED"
    jq -e .Results $S/local$i.json >/dev/null || echo "SCAN $i FAILED"
    jq -r '[.Results[].Vulnerabilities[]?.VulnerabilityID] | unique[]' $S/local$i.json > $S/ids$i
done
diff -q $S/ids1 $S/ids2 && echo STABLE
# control: the Go binary must still show packages, else the scan saw nothing
jq '[.Results[] | select(.Type=="gobinary") | .Packages // [] | length] | add' $S/local1.json
GOTOOLCHAIN=local go run golang.org/x/vuln/cmd/govulncheck@latest ./...   # expect 0 called
```

Both scans use the same DB (no DB update in between). Require STABLE, and a
non-zero control count.

## 8. Report

- **Fixed**: | pkg | old → new | CVEs | commit |
- **Remaining**: | pkg | CVEs | severity | reachable? | reason |
- Trivy DB date (step 2).
- Open PRs that need a rebase (step 1).
- Consumers pinning the image tag pick up the fixes only after a new release.
- Local commits only; wait for "push".
