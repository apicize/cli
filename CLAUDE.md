# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Apicize CLI (`apicize-run`) is a Rust-based command-line tool for running Apicize workbooks, dispatching HTTP requests, and executing tests. The application reads workbooks (`.apicize` files), executes API requests, validates responses with tests, and generates formatted reports.

Exit codes:
- 0: All requests successful and tests passed
- \>0: Number of failed requests or tests
- <0: Program error

## Development Commands

### Build
```bash
cargo build              # Debug build
cargo build --release    # Release build (optimized)
```

### Test
```bash
cargo test              # Run all tests
```

### Lint
```bash
cargo clippy            # Run linter
```

### Package
```bash
cargo deb                           # Build .deb package (Linux)
cargo generate-rpm                  # Build .rpm package (Linux)
cargo wix                           # Build .msi package (Windows, requires cargo-wix)
```

### Run
```bash
cargo run -- <workbook-file>                    # Basic usage
cargo run -- --help                             # Show help
cargo run -- --validate <workbook-file>         # Validate without running
cargo run -- --trace /tmp/trace.log <file>      # Enable HTTP tracing
```

## Architecture

### Single Binary Structure
This is a single-file Rust application (`src/main.rs`) that serves as a CLI wrapper around the `apicize_lib` library crate, which contains the core workbook execution logic.

### Key Components

**CLI Entry Point** (`main()` at line 688):
- Async tokio runtime with single-threaded flavor
- Parses command-line arguments using `clap`
- Searches for workbook files in multiple locations (current dir, configured dir, documents/apicize)
- Opens workbooks and validates them before execution
- Runs requests multiple times if specified (`--runs` parameter)
- Generates output reports in JSON/CSV formats

**Workbook Discovery** (`find_workbook()` at line 131):
- Searches in current directory first
- Checks configured workbook directory from `~/.config/apicize/settings.json` (Linux) or `%APPDATA%\apicize` (Windows)
- Falls back to default documents directory (`~/Documents/apicize`)
- Automatically appends `.apicize` extension if missing

**Result Rendering** (`render_*` functions starting at line 228):
- Hierarchical rendering of test results with indentation
- Groups, requests, rows (data-driven tests), and runs (repeated execution)
- Color-coded output: green (success), yellow (failure), red (error), cyan (HTTP details)
- Timestamps and duration tracking for all operations

**HTTP Tracing** (`ReqwestLogger` at line 1068):
- Custom logger implementation for debugging HTTP traffic
- Captures connection establishment, read/write operations
- Writes timestamped trace to specified file
- Uses regex to parse reqwest verbose output

**Tallies & Summaries** (`render_tallies()` at line 597):
- Tracks success/failure counts for requests and tests
- System locale-aware number formatting
- Aggregates results across multiple runs
- Grand total displayed at end of execution

### Data Flow
1. Parse CLI arguments → 2. Load workbook (from file/stdin) → 3. Apply overrides (defaults, data seeds, passwords) → 4. Validate workbook → 5. Execute requests (with TestRunnerContext from apicize_lib) → 6. Render results to terminal → 7. Write output files (test results JSON, reports CSV/JSON) → 8. Exit with appropriate code

### Dependencies
The CLI wraps `apicize_lib` which provides:
- `Workspace`: Workbook model and loader
- `ApicizeRunner`: Request execution engine
- `TestRunnerContext`: Shared execution context
- `Parameters`: Global parameters (authorizations, certificates, proxies)
- Result types: `ApicizeResult`, `ApicizeGroupResult`, `ApicizeRequestResult`

## Platform-Specific Notes

### Linux
- Vendored OpenSSL (statically linked) for x86_64-unknown-linux-gnu target
- Supports both .deb and .rpm packaging

### Windows
- Uses WinAPI for Windows-specific functionality
- WiX-based MSI installer

### macOS
- Builds for Apple Silicon (aarch64-apple-darwin)
- Distributed as tarball

## Debugging

The VSCode launch configuration in `.vscode/launch.json` shows example debug setup:
- Pre-launch task builds the CLI
- Example args: `--report-csv /tmp/test.csv --report-json /tmp/test.json demo`
- Environment variable `APICIZE_PRIVATE_PWD` can be set for encrypted parameter files
- RUST_BACKTRACE=full enabled for debugging

## Release Process

Releases are automated via GitHub Actions (`.github/workflows/main.yml`):
1. Tag triggers the workflow
2. Runs lint and test jobs
3. Builds platform-specific packages in parallel
4. Attaches all artifacts to GitHub release
