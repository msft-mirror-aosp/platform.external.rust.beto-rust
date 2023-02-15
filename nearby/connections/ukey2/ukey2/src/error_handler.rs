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

#[derive(Clone)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

pub trait ErrorHandler: Send {
    #[track_caller]
    fn log_err(&self, severity: Severity, message: String) {
        self.log_full_err(
            severity,
            message,
            std::panic::Location::caller().file(),
            std::panic::Location::caller().line(),
        )
    }

    fn log_full_err(
        &self,
        severity: Severity,
        message: String,
        origin_file: &str,
        origin_line: u32,
    );
}

/// An [ErrorHandler] that does nothing.
#[derive(Default)]
pub struct NoOpHandler {}

impl ErrorHandler for NoOpHandler {
    fn log_full_err(&self, _severity: Severity, _message: String, _file: &str, _line: u32) {
        // no op
    }
}
