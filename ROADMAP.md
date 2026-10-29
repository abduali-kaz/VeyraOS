# Veyra OS — Roadmap to 1.0 Stable

## Current state: 0.1.0 Alpha

Veyra OS is an experimental Arch-based Linux distribution.
The project includes a KDE Plasma live environment, Veyra Core
CLI tools, diagnostic and recovery commands, a package repository,
and an experimental installer.

The installer is not yet considered safe for production use.

## Milestones

### 1. Foundation
- [ ] Keep generated build artifacts out of Git.
- [ ] Document a reproducible build process.
- [ ] Expand automated tests and CI checks.
- [ ] Document project architecture and contribution rules.

### 2. Veyra Core
- [ ] Stabilize status, storage, diagnose and recovery commands.
- [ ] Improve error messages and report export.
- [ ] Test command behavior and safety boundaries.
- [ ] Document every public command.

### 3. Desktop experience
- [ ] Consistent Veyra branding across boot and desktop.
- [ ] Custom wallpaper, icons and application menu.
- [ ] First-run setup experience.
- [ ] Verify networking, audio, display manager and shutdown.

### 4. Installer
- [ ] Complete preflight validation.
- [ ] Test UEFI installation in an isolated QEMU VM.
- [ ] Add clear partition selection and safety checks.
- [ ] Verify user creation, bootloader, reboot and login.
- [ ] Test failure handling and recovery.
- [ ] Never test destructive operations on a developer's host disks.

### 5. Packages and updates
- [ ] Verify repository and package signatures.
- [ ] Document repository enrollment and key fingerprints.
- [ ] Test install, update and removal workflows.
- [ ] Document recovery from failed updates.

### 6. Release engineering
- [ ] Reproducible ISO build instructions.
- [ ] Automated formatting, tests and build checks.
- [ ] Verify ISO boot and installation in a fresh VM.
- [ ] Publish checksums, release notes and installation guide.

## 1.0 acceptance criteria

- A fresh UEFI virtual machine can install and boot the system.
- Login, networking, desktop, audio and shutdown are tested.
- Package management and recovery behavior are documented.
- Critical safety tests pass.
- Release assets have verified checksums.
- No known critical installation or data-loss bugs remain.

## Development policy

Keep alpha releases available while developing.
Do not label the system stable until the acceptance criteria pass.
Build and test in virtual machines before using real hardware.
