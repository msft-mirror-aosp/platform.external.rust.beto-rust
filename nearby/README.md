# Nearby Rust

## Folder Structure

Root repo of the nearby Rust components, folder structure:

`/connections` nearby connections rust components

`/crypto` shared crypto components

`/presence` nearby presence rust components

## Setup

### Toolchain

If you don't already have a Rust toolchain, see [rustup.rs](https://rustup.rs/).

### Cargo

Install [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):
```
cargo install --locked cargo-deny
cargo install cargo-fuzz
```

### AES on aarch64

To enable RustCrypto AES acceleration on aarch64 (ARMv8) with the nightly toolchain:

```toml
[build]
# only needed when the project is in CitC workspace
target-dir = "/usr/local/google/home/YOUR-USERNAME-HERE/.cache/cargo-target/np-crypto-exp"
# enable AES intrinsics on ARMv8
rustflags = ["--cfg", "aes_armv8"]
```

The benchmarks in `ldt` apparently don't honor that Cargo config, so they need
their own in

`ldt/.cargo/config.toml`:

```tomls
[build]
# only needed when the project is in CitC workspace
target-dir = "/usr/local/google/home/YOUR-USERNAME-HERE/.cache/cargo-target/ldt"
```

You'll know it's working if after building everything and running benchmarks,
you don't have any `target` directories that show up in `hg st` or the like.

### Setting up a Docker dev environment
Our project requires specific versions of system dependencies like OpenSSL and
protobuf in order to build correctly. To make the setup of this easier you can use Docker
to handle setting up the environment in a container.

First install Docker then build and run the image:

```
sudo docker build -t nearby_rust:v1.0 .
sudo docker run --rm -it nearby_rust:v1.0
```
Building the image creates a snapshot of the environment that has all of the system dependencies needed to start building and running all of the artifacts in the codebase.

Running the image runs check-everything.sh to verify all of the targets can successfully build and all of the tests pass in your new container environment.

To open a bash shell from the container environment:
```
sudo docker run -it nearby_rust:v1.0 bash
```

You can also setup VSCode to [develop in a Docker container on a remote host](https://code.visualstudio.com/remote/advancedcontainers/develop-remote-host) that way you can make code changes and test them in the same environment without having to re-build the image.

### Installing addlicense Tool
This tool helps lint the project for the correct header files being present and is run in check_everything.sh

install go:
```sh
brew install go
```
Then install the addlicense tool:
```sh
go install github.com/google/addlicense@latest
```
Verify that it works:
```sh
$HOME/go/bin/addlicense -h
```
Then to auto generate the headers run:
```sh
$HOME/go/bin/addlicense -c "Google LLC" -l apache .
```
For more detailed commands see: https://github.com/google/addlicense

## Common tasks

Check everything:

```
./scripts/check-everything.sh
```

Build everything:

```
cargo build --workspace --all-targets
```

Run tests:

```
cargo test --workspace
```

Generate Docs:

```
cargo doc --no-deps --workspace --open
```

Run linter on dependencies as configured in `deny.toml` <br>
This will make sure all of our dependencies are using valid licenses and check for known existing security
vulnerabilities, bugs and deprecated versions
```
cargo deny --workspace check
```

Update dependencies in `Cargo.lock` to their latest in the currently specified version ranges (i.e. transitive deps):

```
cargo update
```

Check for outdated dependencies with [cargo-outdated](https://github.com/kbknapp/cargo-outdated):

```
cargo outdated
```

## Benchmarks

Benchmarks are in `benches`, and use
[Criterion](https://bheisler.github.io/criterion.rs/book/getting_started.html) .

```
cargo bench --workspace
```
