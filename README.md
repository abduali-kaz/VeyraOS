# Veyra OS

Experimental Arch Linux-based operating system.

## Components
- Veyra Core: Rust system information tools.
- Veyra Setup: installation configuration prototype.
- Veyra Installer: dry-run and plan validation.
- Veyra Storage: read-only disk inspection.
- Veyra Package: early interface backed by pacman.
- Archiso profile: experimental KDE Plasma live environment.

## Development
Requirements: Rust, Cargo, Git, Arch Linux and Archiso.

Run cargo fmt --check, cargo check and cargo run -- status to test the project.

## Roadmap
- Rust package manager and Veyra repository.
- Signed package metadata.
- GitHub Actions for package builds and publishing.
- System diagnostics and recovery tools.

The project is experimental. The installer does not yet perform a real installation.
