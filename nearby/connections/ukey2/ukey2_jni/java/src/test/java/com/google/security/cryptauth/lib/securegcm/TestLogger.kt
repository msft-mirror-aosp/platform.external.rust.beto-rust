/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.security.cryptauth.lib.securegcm

object TestLogger : Ukey2Logger {
  var level: Int = 0
  var message: String = ""
  var originFile: String = ""
  var originLine: Int = 0

  override fun log(level: Int, message: String?, originFile: String, originLine: Int) {
    this.level = level
    this.message = message ?: ""
    this.originFile = originFile
    this.originLine = originLine
  }
}