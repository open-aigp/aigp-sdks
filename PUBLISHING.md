# AIGP SDK — Publishing Guide

How to publish AIGP SDK packages to their language registries.

> Status note: core SDK implementations are available for Python, TypeScript, Go, Rust, Java, Kotlin, and .NET.
> Registry publish status still varies by language.
> Check each SDK README before production use.

---

## Registry Summary

| Language | Registry | Package Name | Install Command |
|----------|----------|-------------|----------------|
| Python | PyPI | `aigp` | `pip install aigp` |
| TypeScript | npm | `@aigp/sdk` | `npm install @aigp/sdk` |
| Rust | crates.io | `aigp` | `cargo add aigp` |
| Java | Maven Central | `org.open-aigp:aigp-sdk` | `<dependency>` in pom.xml |
| Kotlin | Maven Central | `org.open-aigp:aigp-kotlin-sdk` | `<dependency>` in build.gradle/pom.xml |
| C# / .NET | NuGet | `AIGP.Sdk` | `dotnet add package AIGP.Sdk` |
| Go | Go Modules | `github.com/open-aigp/aigp/sdks/go` | `go get github.com/open-aigp/aigp/sdks/go` |

---

## 1. npm — `@aigp/sdk`

**Directory:** `sdks/typescript/`

### One-time setup
1. Create an npm account at https://www.npmjs.com/signup
2. Create the `@aigp` org at https://www.npmjs.com/org/create (free for public packages)
3. Create a **Granular Access Token** at https://www.npmjs.com/settings/<username>/tokens:
   - Permissions: **Read and write**
   - Packages: scope to `@aigp`
   - **Check "Bypass two-factor authentication (2FA)"** — required for CLI publishing
4. Set the token locally:
   ```bash
   npm config set //registry.npmjs.org/:_authToken=npm_XXXXXX
   ```

### Publish
```bash
cd sdks/typescript
npm publish --access public
```

### Verify
https://www.npmjs.com/package/@aigp/sdk

**Status:** ✅ Published v0.1.0 (Feb 2026)

---

## 2. crates.io — `aigp`

**Directory:** `sdks/rust/`

### One-time setup
1. Install Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```
2. Login to crates.io (authenticates via GitHub):
   ```bash
   cargo login
   ```
   This opens https://crates.io/settings/tokens — create a token and paste it.
3. **Verify your email** at https://crates.io/settings/profile (required to publish)

### Publish
```bash
cd sdks/rust
cargo publish
```

### Dry-run first
```bash
cargo publish --dry-run
```

### Verify
https://crates.io/crates/aigp

**Status:** ✅ Published v0.1.0 (Feb 2026)

---

## 3. PyPI — `aigp`

**Directory:** `sdks/python/`

> **Note:** Both `pip install aigp` and `pip install aigp-python` work.
> The canonical package name is `aigp`. The older `aigp-python` name still exists on PyPI.

### One-time setup
1. Create a PyPI account at https://pypi.org/account/register/
2. Create an API token at https://pypi.org/manage/account/token/
   - Scope: **Entire account** (for first upload; can scope to project after)
3. Install build tools:
   ```bash
   pip install build twine
   ```
4. Save token in `~/.pypirc`:
   ```ini
   [pypi]
   username = __token__
   password = pypi-XXXXXX
   ```

### Publish
```bash
cd sdks/python
python -m build
twine upload dist/*
```

### Verify
https://pypi.org/project/aigp/

**Status:** ✅ Published v1.0.0 (Feb 2026)

---

## 4. Maven Central — `org.open-aigp:aigp-sdk`

**Directory:** `sdks/java/`

### One-time setup (most involved)
1. Register at https://central.sonatype.com (sign in with GitHub)
2. **Verify domain ownership** for `org.open-aigp`:
   - Add a TXT record to `open-aigp.org` DNS as instructed by Sonatype
   - This proves you own the `org.open-aigp` namespace
3. Install GPG and generate a signing key:
   ```bash
   brew install gnupg
   gpg --gen-key
   gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
   ```
4. Configure Maven settings in `~/.m2/settings.xml`:
   ```xml
   <settings>
     <servers>
       <server>
         <id>central</id>
         <username>YOUR_SONATYPE_USERNAME</username>
         <password>YOUR_SONATYPE_TOKEN</password>
       </server>
     </servers>
   </settings>
   ```
5. Add the `maven-gpg-plugin` and `nexus-staging-maven-plugin` to `pom.xml`

### Publish
```bash
cd sdks/java
mvn clean deploy -P release
```

### Alternative: Manual upload
Upload the JAR directly at https://central.sonatype.com/publishing

### Verify
https://search.maven.org/search?q=g:org.open-aigp%20AND%20a:aigp-sdk

**Status:** ✅ Namespace verified (Feb 2026). JAR publish pending (requires GPG signing + Maven deploy).

---

## 5. NuGet — `AIGP.Sdk`

**Directory:** `sdks/dotnet/`

### One-time setup
1. Install .NET SDK:
   ```bash
   brew install dotnet-sdk
   ```
2. Create a NuGet account at https://www.nuget.org/
3. Create an API key at https://www.nuget.org/account/apikeys:
   - Package owner: your account
   - Glob pattern: `AIGP.*`
   - Scopes: **Push**

### Publish
```bash
cd sdks/dotnet
dotnet pack -c Release
dotnet nuget push bin/Release/AIGP.Sdk.0.1.0.nupkg \
  --api-key YOUR_API_KEY \
  --source https://api.nuget.org/v3/index.json
```

### Verify
https://www.nuget.org/packages/AIGP.Sdk

**Status:** ⚠ Verify latest package availability on NuGet before production rollout.

---

## 6. Go — `github.com/open-aigp/aigp/sdks/go`

**Directory:** `sdks/go/`

### One-time setup
None — Go uses git repos directly. No registry account needed.

### Publish
Just push to GitHub and tag:
```bash
git add sdks/go/
git commit -m "Release Go SDK v0.1.0"
git tag sdks/go/v0.1.0
git push origin main --tags
```

### Verify
```bash
go get github.com/open-aigp/aigp/sdks/go@v0.1.0
```

**Status:** ⏳ Pending (just needs git push + tag)

---

## 7. Kotlin — `org.open-aigp:aigp-kotlin-sdk`

**Directory:** `sdks/kotlin/`

### One-time setup
Same Sonatype namespace + GPG setup as Java (Section 4).

### Publish
```bash
cd sdks/kotlin
gradle publish
```

### Verify
https://search.maven.org/search?q=g:org.open-aigp%20AND%20a:aigp-kotlin-sdk

**Status:** ⏳ Pending (package and publish pipeline setup required)

---

## Version Bump Checklist

When releasing a new version across all SDKs:

1. **Python**: Update `version` in `sdks/python/pyproject.toml` and `__version__` in `sdks/python/aigp/__init__.py`
2. **TypeScript**: Update `version` in `sdks/typescript/package.json`
3. **Rust**: Update `version` in `sdks/rust/Cargo.toml`
4. **Java**: Update `<version>` in `sdks/java/pom.xml`
5. **C# / .NET**: Update `<Version>` in `sdks/dotnet/AIGP.Sdk.csproj`
6. **Go**: Create a new git tag `sdks/go/vX.Y.Z`
7. **Kotlin**: Update `version` in `sdks/kotlin/build.gradle.kts`

---

## Name Reservations Status

| Registry | Name | Status | Date |
|----------|------|--------|------|
| npm | `@aigp/sdk` | ✅ Published | Feb 2026 |
| crates.io | `aigp` | ✅ Published | Feb 2026 |
| PyPI | `aigp` | ✅ Published | Feb 2026 |
| Maven Central | `org.open-aigp:aigp-sdk` | ✅ Namespace verified | Feb 2026 |
| Maven Central | `org.open-aigp:aigp-kotlin-sdk` | ⏳ Pending | — |
| NuGet | `AIGP.Sdk` | ⚠ Verify latest package availability | Feb 2026 |
| Go Modules | (git-based) | ⏳ Pending | — |
