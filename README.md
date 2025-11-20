# go-tpm-kit

![go version](https://img.shields.io/github/go-mod/go-version/loicsikidi/go-tpm-kit)
[![godoc](https://pkg.go.dev/badge/github.com/loicsikidi/grpctest/v1.svg)](https://pkg.go.dev/github.com/loicsikidi/go-tpm-kit)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue?style=flat-square)](https://raw.githubusercontent.com/loicsikidi/go-tpm-kit/main/LICENSE)

This library aims to be a swiss-army knife for working with TPMs in Go.

> [!WARNING]
> ⚠️ This tool is currently in beta mode and its usage might change without announcements.
>
> *Note: once the API will be stable `v1.0.0` will be released.*

## Motivation

[`go-tpm`](https://github.com/google/go-tpm) is a great library to interact with TPMs in Go. However, it focuses mainly on low-level interactions with TPMs and does not provide higher-level abstractions or utilities that can simplify common tasks. `go-tpm-kit` aims to fill this gap by providing a set of tools and abstractions that make it easier to work with TPMs in Go applications.

I've seen myself re-implementing similar functionalities across different projects, so I decided to create a dedicated library to centralize these utilities and make them reusable.

## Structure

> [!IMPORTANT]
> `go-tpm-kit` only supports "TPMDirect" API (ie, [`go-tpm/tpm2`](https://pkg.go.dev/github.com/google/go-tpm/tpm2) package). In other words, it does not  (and won't) support the legacy API (ie, [`go-tpm/legacy/tpm2`](https://pkg.go.dev/github.com/google/go-tpm/legacy/tpm2) package).

| Package | Description | Require TPM Connection |
|---------|-------------|:----------------------:|
| [`tpmutil`](./tpmutil/) | Provides utility functions to interact with TPMs (e.g., reading/writing NV indices, managing sessions, etc.) | ✅ |
| [`tpmcrypto`](./tpmcrypto/) | Provides cryptographic utilities and abstractions for working with TPM keys and signatures | ❌ |
| [`tpmsession`](./tpmsession/) | Provides utilities for creating and managing encrypted TPM sessions (ie. parameter encryption, HMAC protection and Audit)  | ✅ |

## Dependencies

This repo depends on:
* [`go-tpm`](https://github.com/google/go-tpm) - TPM 2.0 library for Go
* [`golang.org/x/term`](https://pkg.go.dev/golang.org/x/term) - Terminal utilities for secure password input

## Development

### Prerequisites

This project uses Nix for dependency management. To enter the development environment:

```bash
nix-shell
```

> [!TIP]
> This will also add git hooks thanks to [githooks.nix](https://github.com/cachix/git-hooks.nix).

### Lint code

```bash
nix-shell --run "lint"
```

### Run tests

```bash
nix-shell --run "gotest"
```

## License

BSD-3-Clause License. See the [LICENSE](LICENSE) file for details.

## Name

`go-tpm-kit` can be read as "Go TPM toolkit". I've silenced the *tool* from *toolkit* to avoid any confusion with another repo named ["go-tpm-tools"](https://github.com/google/go-tpm-tools).

## Disclaimer

This is my personal project and it does not represent my employer. While I do my best to ensure that everything works, I take no responsibility for issues caused by this code.
