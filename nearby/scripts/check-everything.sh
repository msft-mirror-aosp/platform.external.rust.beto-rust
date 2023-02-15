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

set -ex

cd "$(dirname "$0")"/..

# see README for instructions on setting up addlicense tool
if ($HOME/go/bin/addlicense -h >/dev/null 2>&1) ; then
    echo "Add license is already installed"
else
    echo "ERROR: addlicense tool is not installed, see instructions in README"
    exit
fi

if $HOME/go/bin/addlicense -check -ignore=target/** -ignore=**/target/** -ignore=".idea/*" -ignore=**/cmake-build/** -ignore="**/java/build/**" . ; then
    echo "License header check succeeded!"
else
    echo "ERROR: License header missing for above files"
    exit
fi

# ensure formatting is correct (Check for it first because it is fast compared to running tests)
cargo fmt --check

# make sure everything compiles
cargo check --workspace --all-targets

# run all the tests
cargo test --workspace --quiet

# ensure the docs are valid (cross-references to other code, etc)
cargo doc --workspace --no-deps

cargo clippy --all-targets

cargo deny --workspace check

# Check the build for targets without using RustCrypto dependencies
cargo check --features=openssl --no-default-features

# We need to handle ldt_np_adv_ffi separately since it requires the nightly toolchain
cd presence/ldt_np_adv_ffi
cargo fmt --check
cargo check
cargo build --release
cargo test --quiet
cargo doc --no-deps
cargo clippy --all-targets
cargo deny check
cd ..

# build C/C++ samples, tests, and benches
mkdir -p cmake-build && cd cmake-build
cmake .. -DENABLE_TESTS=true
make

# test with default build settings (rustcrypto, no_std)
(cd ldt_np_c_sample/tests && ctest)

# test with openssl crypto feature flag
(cd ../ldt_np_adv_ffi && cargo build --features openssl --release)
(cd ldt_np_c_sample/tests && make && ctest)

# test with std feature flag
(cd ../ldt_np_adv_ffi && cargo build --features std --release)
(cd ldt_np_c_sample/tests && make && ctest)

# back to cargo workspace root
cd ../..

"./scripts/build-fuzzers.sh"

"./scripts/prepare-boringssl.sh"
cargo --config .cargo/config-boringssl.toml test --all-targets --features=boringssl
