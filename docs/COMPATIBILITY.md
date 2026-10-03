# Compatibility policy

This page says what a go-luks2 version number promises, and how that changes
at the first public release.

## Versions

Versions are [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html),
`MAJOR.MINOR.PATCH`, with a `v` prefix on the tag (`v0.3.0`) and none in the
`VERSION` file (`0.3.0`). Internal builds between releases carry `-alpha`
(`v0.3.0-alpha`); they make no promise to anyone outside this project.

go-luks2 is pre-1.0. In a `0.y.z` line:

| Bump | Means |
|---|---|
| PATCH (`0.3.0` → `0.3.1`) | A fix. No exported API changes, no change to what is written to disk. |
| MINOR (`0.3.x` → `0.4.0`) | New API, **or a breaking change**. Pre-1.0, a breaking change is announced by a MINOR bump, never a PATCH one. |
| MAJOR | Reserved for `1.0.0`, when the API is settled. After 1.0 a breaking change is a new major version, and the module path gains `/vN`. |

A breaking change is anything that can stop a correct consumer compiling, or
change what it observes: a removed or renamed exported identifier, a changed
signature, a changed error a caller is documented to match, a refused input
that used to be accepted, or a change to what is written to a LUKS2 header.

## Before the first public release

Until the first public release, backward compatibility was a non-goal: the
API, the on-disk choices and the command line changed whenever the
technically right design required it, with no shims, aliases or migration
paths. Those changes are recorded in `CHANGELOG.md` with `BREAKING:` in their
headings.

## From the first public release on

- **A breaking change bumps MINOR** (pre-1.0) and its `CHANGELOG.md` entry
  carries `BREAKING:` in its heading, with what a consumer must change.
- **A breaking change lands with its consumers.** Projects that depend on
  go-luks2 are updated, built and tested against the new version before it is
  released, from the bottom of the dependency graph up; a change that cannot
  be walked up is not released alone.
- **Published tags are immutable.** A tag is never moved or deleted. A wrong
  release is superseded by the next version, which is how a revert ships too.
- **Versions only go up.** The `VERSION` file is never lowered, and a
  consumer is never asked to pin a lower version than one it already uses.
- **The LUKS2 on-disk format is cryptsetup's**, not this project's. A header
  go-luks2 writes is one cryptsetup opens, and the reverse; changing that is a
  defect, not a breaking change.

There is no deprecation window before 1.0: an API is removed in the MINOR
release that announces it. A deprecation policy will be stated here before
1.0.
