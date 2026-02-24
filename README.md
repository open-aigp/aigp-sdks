# AIGP SDKs

Language SDKs for the AIGP open specification.

This repository hosts all SDKs in one monorepo:

- `python/`
- `typescript/`
- `go/`
- `rust/`
- `java/`
- `kotlin/`
- `dotnet/`

## Source of truth

- Specification and normative schemas live in the spec repo: `open-aigp/aigp`.
- Conformance fixtures are mirrored in `conformance/validation-fixtures.tsv` and should be synced from the spec repo.

## Design goals

- Spec parity across all SDKs.
- Vendor-agnostic transport and crypto boundaries.
- Backward compatibility for non-breaking spec updates.

## Typical validation commands

```bash
cd python && python -m pytest -q
cd ../typescript && npm test
cd ../go && go test ./...
cd ../rust && cargo test
cd ../java && mvn test
cd ../kotlin && gradle test
cd ../dotnet && dotnet run --project tests/AIGP.Sdk.SmokeTests/AIGP.Sdk.SmokeTests.csproj
```
