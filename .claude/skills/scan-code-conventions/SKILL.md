---
name: scan-code-conventions
desc: Audit and update the repo-dev skill (SKILL.md) to reflect the current state of the codebase
allowed-tools: Read, Grep, Glob, Write, Edit, Bash, Task, AskUserQuestion, TodoWrite
---

# Coding Conventions Maintenance Process

This skill keeps `.claude/skills/repo-dev/SKILL.md` synchronized with the actual codebase.
It follows a 4-phase pipeline: **Scan -> Diff -> Report -> Update**.

Every phase must complete before moving to the next. The human approves the report before any update is made.

---

## Phase 1: Scan

Perform a comprehensive audit of the codebase to extract the **current reality**. Collect the following data points by scanning actual source files (exclude `vendors/`):

### 1.1 Structural inventory

- List all Go packages (directories containing `.go` files)
- For each package, list all `.go` files (source + test) with a one-line description of their content
- Identify any new packages or files not mentioned in the current SKILL.md

### 1.2 Pattern extraction

For each package, verify the presence/absence of these documented patterns:

| Pattern | What to check |
|---------|---------------|
| License header | First 4 lines of every `.go` file |
| Import grouping | 3-group separation (stdlib / external / internal) |
| `CheckAndSetDefault()` | All config structs have this method |
| Variadic optional config | Public functions using `utils.OptionalArg()` |
| Public/private split | Exported func delegates to unexported impl |
| Sentinel errors | `var ( Err... = errors.New(...) )` blocks |
| Custom error types | Structs with `Error()` + `Unwrap()` |
| Enum types | `const + iota` with `String()` method |
| Table-driven tests | `tests := []struct { ... }` pattern |
| External test package | `package <pkg>_test` |
| Godoc conventions | Exported symbols start with their name, use `[DocLinks]` |
| Constructor naming | `New*`, `Must*`, `Get*`, `Create*`, `*WithResult` |
| Interface design | Small interfaces, unexported implementations |
| Resource cleanup | `HandleCloser`, `t.Cleanup()`, `defer` |
| Concurrency | `sync.RWMutex`, `atomic.Pointer` usage |
| Build tags | `//go:build` tags for platform-specific tests |

### 1.3 Metadata extraction

- Go version from `go.mod`
- Primary dependency version from `go.mod`
- Module path from `go.mod`
- Any new dependencies that might be worth documenting

### 1.4 Convention drift detection

Look for patterns that exist in code but are NOT documented in SKILL.md:
- New file naming conventions
- New configuration patterns
- New testing patterns
- New error handling patterns
- New type patterns

---

## Phase 2: Diff

Compare scan results against the current `.claude/skills/repo-dev/SKILL.md` and produce a structured diff:

### 2.1 Categories

Classify every finding into one of these categories:

| Category | Symbol | Meaning |
|----------|--------|---------|
| Addition | `[+]` | Pattern/file/package exists in code but not in SKILL.md |
| Removal | `[-]` | Pattern/file/package documented in SKILL.md but no longer exists in code |
| Modification | `[~]` | Pattern/file/package exists in both but details have changed |
| Unchanged | `[=]` | No change needed (do not list these in the report) |

### 2.2 Diff structure

For each finding, record:
- **Location**: Which section of SKILL.md is affected (e.g., "2.1 File Layout")
- **Category**: `[+]`, `[-]`, `[~]`
- **Description**: What changed
- **Evidence**: File path + line number showing the current state
- **Suggested action**: Specific text addition/removal/modification

---

## Phase 3: Report

Write the audit report to `.claude/notes/conventions-audit-report.md` with the following structure:

```markdown
# Conventions Audit Report

**Date**: YYYY-MM-DD
**SKILL.md version**: (git hash of last commit touching SKILL.md)
**Codebase HEAD**: (current git HEAD hash)

## Summary

- X additions, Y removals, Z modifications found
- Overall drift level: Low / Medium / High

## Findings

### Additions [+]

#### [+] <title>
- **Section**: <SKILL.md section>
- **Evidence**: `<file>:<line>`
- **Suggested change**: <description>

### Removals [-]

#### [-] <title>
...

### Modifications [~]

#### [~] <title>
...

## Recommended SKILL.md updates

<Ordered list of concrete changes to apply, from most to least important>
```

### 3.1 Human review gate

After writing the report:

1. Tell the human: "The audit report is ready at `.claude/notes/conventions-audit-report.md`"
2. Ask the human to review using `AskUserQuestion`:
   - "Apply all changes"
   - "Apply selectively" (then ask which findings to include/exclude)
   - "Abort" (no changes made)

Do NOT proceed to Phase 4 without explicit approval.

---

## Phase 4: Update

Apply the approved changes to `.claude/skills/repo-dev/SKILL.md`:

### 4.1 Update rules

- Preserve the existing document structure (sections, numbering)
- Add new sections at the end of their parent section
- Update file layout tables in-place
- Update metadata (Go version, dependency versions) in-place
- Keep code examples accurate: if a code example has changed, update it by reading the actual source
- Never remove a section entirely without explicit human approval
- Maintain the same markdown formatting style

### 4.2 Post-update verification

After applying changes:

1. Read back the updated SKILL.md to verify formatting
2. Confirm the number of changes applied matches the approved list
3. Report completion to the human with a summary of what was updated

### 4.3 Cleanup

- Delete `.claude/notes/conventions-audit-report.md` (it was a transient artifact)
- The updated SKILL.md is the durable output

---

## Quick reference: Triggering this skill

Use `/scan-code-conventions` to run the full pipeline. The process is interactive:
you will be asked to approve the report before any changes are made.

Typical run:
1. Agent scans codebase (~30s)
2. Agent produces diff against current SKILL.md
3. Agent writes report and asks for approval
4. Human reviews and approves/selects/aborts
5. Agent applies approved changes to SKILL.md
