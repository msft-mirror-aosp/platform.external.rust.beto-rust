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

//! # RemoteAuthPlatform
//!
//! This trait represents the capabilities that RemoteAuth requires from the platform.

use async_trait::async_trait;

#[async_trait]
pub trait Platform {
    /// Send a binary message to the remote with the given connection id and return the response.
    async fn send_request(&self, connection_id: i32, request: &[u8]) -> anyhow::Result<Vec<u8>>;
}
