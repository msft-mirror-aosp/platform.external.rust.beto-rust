#!/bin/sh
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Run this script to prepare the workspace for testing against BoringSSL.
# If you don't, you'll see the following error when trying to build:
# ```
# $ cargo test --features=boringssl
# error: This is a placeholder package not intended for use - see README.md
#  --> ~/.cargo/registry/src/github.com-1ecc6299db9ec823/bssl-sys-0.1.0/src/lib.rs:1:1
#   |
# 1 | compile_error!("This is a placeholder package not intended for use - see README.md");
#   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# ```


set -ex

cd "$(dirname "$0")"/../..
projectroot=$PWD


mkdir -p boringssl-build && cd boringssl-build

if ! git -C boringssl pull origin master; then
  git clone https://boringssl.googlesource.com/boringssl
fi
cd boringssl && mkdir -p build && cd build
cmake -G Ninja .. -DRUST_BINDINGS="$(gcc -dumpmachine)" && ninja
# A valid Rust crate is built under `boringssl-build/boringssl/build/rust`

cd $projectroot/boringssl-build
if ! git -C rust-openssl pull origin master; then
  git clone https://github.com/sfackler/rust-openssl.git
fi
git -C rust-openssl checkout 11797d9ecb73e94b7f55a49274318abc9dc074d2
git -C rust-openssl branch -f BASE_COMMIT
git -C rust-openssl am $projectroot/nearby/scripts/openssl-patches/*.patch

set +x

cd $projectroot

cat <<'EOF' >&2
==========
Preparation complete. The required repositories are downloaded to `beto-rust/boringssl-build`. If
you need to go back to a clean state, you can remove that directory and rerun this script.

You can now build and test with boringssl using the following command
  `cd nearby && cargo --config .cargo/config-boringssl.toml test --features=boringssl`
==========
EOF
echo
