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

# Build all fuzz targets

project_dir=$(dirname "$0")/..

# rust fuzzers
for fuzzed_crate in presence/xts_aes presence/ldt presence/ldt_np_adv connections/ukey2/ukey2_connections; do
  ( cd "$project_dir/$fuzzed_crate" && cargo +nightly fuzz build )
done

# ffi fuzzers
rm -Rf $project_dir/presence/ldt_np_adv_ffi_fuzz/cmake-build
(cd $project_dir/presence/ldt_np_adv_ffi_fuzz && mkdir -p cmake-build && cd cmake-build && cmake ../.. && make)
rm -Rf $project_dir/presence/ldt_np_adv_ffi_fuzz/cmake-build
