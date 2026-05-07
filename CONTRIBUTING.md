# Contributing to Dendri

## Development Setup
```bash
cargo build
cargo test
cargo run -- --help
```

## Workflow
1. Fork the repo
2. Create a feature branch (`git checkout -b feature/thing`)
3. Run `cargo test` and `cargo clippy -- -D warnings`
4. Run `cargo fmt` to format code
5. Open a PR against `main`

## Code Style
- Follow `cargo fmt` output
- Pass `cargo clippy -- -D warnings` with zero warnings
- Write tests for new functionality
- Keep functions focused and under 50 lines

## Reporting Issues
Open a GitHub issue with:
- Description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment (OS, Rust version, `cargo --version`)

## License
By contributing, you agree that your contributions will be licensed under the AGPL-3.0-only license.
