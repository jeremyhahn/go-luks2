# Compatibility policy

> **Status: NORMATIVE** · Last verified: 2026-10-04 against v0.3.1-alpha
> Conflicts with this policy are defects.

## Versions

[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Tags carry a
`v` (`v0.3.1-alpha`); the `VERSION` file does not (`0.3.1-alpha`). `-alpha`
builds are internal and promise nothing outside this project.

go-luks2 is pre-1.0:

| Bump | Means |
|---|---|
| PATCH (`0.3.0` → `0.3.1`) | A fix. No exported API change, no change to what is written to disk. |
| MINOR (`0.3.x` → `0.4.0`) | New API **or a breaking change**. Before 1.0 a breaking change is a MINOR bump, never a PATCH. |
| MAJOR | Reserved for `1.0.0`. After that, a breaking change is a new major version and the module path gains `/vN`. |

A breaking change is anything that can stop a correct consumer compiling or
change what it observes: a removed or renamed exported identifier, a changed
signature, a changed error a caller is documented to match, a refused input
that used to be accepted, or a change to what is written to a LUKS2 header.

## Before the first public release

Backward compatibility was not a goal. API, on-disk choices and CLI changed
when the design required it, with no shims. `CHANGELOG.md` marks those changes
with `BREAKING:` in the heading.

## From the first public release

- A breaking change bumps MINOR (pre-1.0), and its changelog heading carries
  `BREAKING:` and what a consumer must change.
- A breaking change lands with its consumers: dependent projects are updated,
  built and tested against it, bottom of the dependency graph up, before it is
  released.
- Published tags are never moved or deleted. A bad release is superseded by the
  next version.
- Versions only go up.
- The on-disk format is cryptsetup's. A header go-luks2 writes must open in
  cryptsetup and the reverse; breaking that is a defect, not a breaking change.

There is no deprecation window before 1.0: an API is removed in the MINOR
release that announces it. A deprecation policy will be stated here before 1.0.
