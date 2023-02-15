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

interface Ukey2Logger {
  /**
   * This enum defines logging levels, similar to Android's INFO, ERROR, and WARNING levels.
   * These can be used to filter logs and take different actions accordingly.
   */
  enum class Severity {
    Info, Warning, Error;

    companion object {
      /**
       * This can be used to convert from the level reported by native code to a [Severity].
       * @param level
       * @return Severity that can be used like Android's logging levels.
       */
      fun convertLevelToSeverity(level: Int): Severity {
        return when (level) {
          0 -> Info
          1 -> Warning
          else -> Error
        }
      }
    }
  }

  fun log(level: Int, message: String?, originFile: String, originLine: Int)
}