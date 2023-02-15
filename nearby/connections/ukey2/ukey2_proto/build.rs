// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use protoc_rust::Customize;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap() + "/proto";
    std::fs::create_dir_all(&out_dir).unwrap();
    protoc_rust::Codegen::new()
        // All inputs and imports from the inputs must reside in `includes` directories.
        .includes(["proto"])
        // Inputs must reside in some of include paths.
        .input("proto/ukey.proto")
        .input("proto/securemessage.proto")
        .input("proto/securegcm.proto")
        .input("proto/device_to_device_messages.proto")
        .customize(Customize {
            gen_mod_rs: Some(true),
            ..Default::default()
        })
        .out_dir(out_dir)
        .run()
        .unwrap();
}
