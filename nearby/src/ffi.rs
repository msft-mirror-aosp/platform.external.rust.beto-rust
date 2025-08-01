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

use crate::{crypto_ffi, CargoOptions};
use cmd_runner::{run_cmd_shell, run_cmd_shell_with_color, YellowStderr};
use std::{fs, path};

// wrapper for checking all ffi related things
pub fn check_ffi(root: &path::Path, cargo_options: &CargoOptions) -> anyhow::Result<()> {
    crypto_ffi::check_boringssl(root, cargo_options)?;
    check_np_ffi_cmake(root, cargo_options)?;
    check_ldt_cmake(root, cargo_options)?;

    Ok(())
}

pub fn check_np_ffi_cmake(root: &path::Path, cargo_options: &CargoOptions) -> anyhow::Result<()> {
    log::info!("Checking CMake build and tests for np ffi c/c++ code");
    let build_dir = root.join("presence/cmake-build");
    fs::create_dir_all(&build_dir)?;

    let locked_arg = if cargo_options.locked { "--locked" } else { "" };

    run_cmd_shell_with_color::<YellowStderr>(
        &build_dir,
        "cmake -G Ninja -DENABLE_TESTS=true -DCMAKE_BUILD_TYPE=Release -DENABLE_FUZZ=false ..",
    )?;

    // verify sample and benchmarks build
    let np_ffi_crate_dir = root.to_path_buf().join("presence/np_c_ffi");
    run_cmd_shell(&np_ffi_crate_dir, format!("cargo build {locked_arg} --release"))?;
    run_cmd_shell_with_color::<YellowStderr>(&build_dir, "cmake --build . --target np_cpp_sample")?;
    run_cmd_shell_with_color::<YellowStderr>(&build_dir, "cmake --build . --target np_ffi_bench")?;

    // Run tests with different crypto backends
    let tests_dir = build_dir.join("np_cpp_ffi/tests");
    for build_config in [
        // test with default build settings (rustcrypto)
        format!("build {locked_arg} --quiet --release"),
        // test with boringssl
        format!("build {locked_arg} --quiet --no-default-features --features=boringssl"),
    ] {
        let _ = run_cmd_shell_with_color::<YellowStderr>(
            &build_dir,
            "rm np_cpp_ffi/tests/np_ffi_tests",
        );
        run_cmd_shell(&np_ffi_crate_dir, format!("cargo {}", build_config))?;
        run_cmd_shell_with_color::<YellowStderr>(
            &build_dir,
            "cmake --build . --target np_ffi_tests",
        )?;
        run_cmd_shell_with_color::<YellowStderr>(&tests_dir, "ctest")?;
    }

    Ok(())
}

pub fn check_ldt_cmake(root: &path::Path, cargo_options: &CargoOptions) -> anyhow::Result<()> {
    log::info!("Checking CMake build and tests for ldt c/c++ code");
    let build_dir = root.join("presence/cmake-build");
    fs::create_dir_all(&build_dir)?;

    let locked_arg = if cargo_options.locked { "--locked" } else { "" };

    run_cmd_shell_with_color::<YellowStderr>(
        &build_dir,
        "cmake -G Ninja -DENABLE_TESTS=true -DCMAKE_BUILD_TYPE=Release -DENABLE_FUZZ=false ..",
    )?;

    run_cmd_shell(root, format!("cargo build {locked_arg} -p ldt_np_adv_ffi --quiet --release"))?;
    run_cmd_shell_with_color::<YellowStderr>(&build_dir, "cmake --build . --target ldt_c_sample")?;
    run_cmd_shell_with_color::<YellowStderr>(
        &build_dir,
        "cmake --build . --target ldt_benchmarks",
    )?;

    // Run the LDT ffi unit tests. These are rebuilt and tested against all of the different
    // Cargo build configurations based on the feature flags.
    let ldt_tests_dir = build_dir.join("ldt_np_adv_ffi/c/tests");
    for build_config in [
        // test with default build settings (rustcrypto, no_std)
        format!("build {locked_arg} --quiet --release"),
        // test with boringssl crypto feature flag
        format!("build {locked_arg} --quiet --no-default-features --features boringssl --release"),
        // test without defaults and std feature flag
        format!("build {locked_arg} --quiet --no-default-features --features std --release"),
    ] {
        run_cmd_shell(root, format!("cargo {} -p ldt_np_adv_ffi", build_config))?;
        // Force detection of updated `ldt_np_adv_ffi` static lib
        let _ = run_cmd_shell_with_color::<YellowStderr>(&ldt_tests_dir, "rm ldt_ffi_tests");
        run_cmd_shell_with_color::<YellowStderr>(
            &build_dir,
            "cmake --build . --target ldt_ffi_tests",
        )?;
        run_cmd_shell_with_color::<YellowStderr>(&ldt_tests_dir, "ctest")?;
    }

    Ok(())
}
