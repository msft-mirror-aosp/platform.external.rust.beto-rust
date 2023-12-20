// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "nearby_protocol.h"
#include "shared_test_util.h"
#include "np_cpp_test.h"

#include "gtest/gtest.h"

TEST_F(NpCppTest, TestSetMaxCredSlabs) {
  auto slab1_result = nearby_protocol::CredentialSlab::TryCreate();
  ASSERT_TRUE(slab1_result.ok());

  auto slab2_result = nearby_protocol::CredentialSlab::TryCreate();
  ASSERT_TRUE(slab2_result.ok());

  auto slab3_result = nearby_protocol::CredentialSlab::TryCreate();
  ASSERT_TRUE(slab3_result.ok());

  auto slab4_result = nearby_protocol::CredentialSlab::TryCreate();

  ASSERT_FALSE(slab4_result.ok());
  ASSERT_TRUE(absl::IsResourceExhausted(slab4_result.status()));
}

TEST_F(NpCppTest, TestSlabMoveConstructor) {
  auto slab = nearby_protocol::CredentialSlab::TryCreate().value();
  // It should be possible to move the slab into a new object
  // and use the moved version to successfully construct a
  // credential-book.
  nearby_protocol::CredentialSlab next_slab(std::move(slab));

  auto maybe_book = nearby_protocol::CredentialBook::TryCreateFromSlab(next_slab);
  ASSERT_TRUE(maybe_book.ok());

  // Now, both slabs should be moved-out-of, since `TryCreateFromSlab` takes
  // ownership. Verify that this is the case, and attempts to re-use the slabs
  // result in an assert failure.
  ASSERT_DEATH([[maybe_unused]] auto failure =
                nearby_protocol::CredentialBook::TryCreateFromSlab(slab), //NOLINT(bugprone-use-after-move)
               "");
  ASSERT_DEATH([[maybe_unused]] auto failure =
                nearby_protocol::CredentialBook::TryCreateFromSlab(next_slab),
               "");
}
