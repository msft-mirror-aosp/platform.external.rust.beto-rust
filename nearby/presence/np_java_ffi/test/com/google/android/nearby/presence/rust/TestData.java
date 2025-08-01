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

package com.google.android.nearby.presence.rust;

import com.google.android.nearby.presence.rust.credential.V0DiscoveryCredential;
import com.google.android.nearby.presence.rust.credential.V1DiscoveryCredential;

public class TestData {

  public static final byte[] V0_PUBLIC = {
    0x00, // adv header
    0x15, 20, // tx power
    0x26, 0x00, 0x40, // actions
  };

  public static final byte[] V1_PUBLIC = {
    0x20, // NP Version Header
    0x00, // Section format
    0x02, // section len
    0x15, 0x06, // tx power value 6
  };

  public static final byte[] V0_KEY_SEED = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11
  };

  public static final byte[] V0_IDENTITY_TOKEN = {
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33
  };

  public static final byte[] V0_IDENTITY_TOKEN_HMAC = {
    (byte) 0x09,
    (byte) 0xFE,
    (byte) 0x9E,
    (byte) 0x81,
    (byte) 0xB7,
    (byte) 0x3E,
    (byte) 0x5E,
    (byte) 0xCC,
    (byte) 0x76,
    (byte) 0x59,
    (byte) 0x57,
    (byte) 0x71,
    (byte) 0xE0,
    (byte) 0x1F,
    (byte) 0xFB,
    (byte) 0x34,
    (byte) 0x38,
    (byte) 0xE7,
    (byte) 0x5F,
    (byte) 0x24,
    (byte) 0xA7,
    (byte) 0x69,
    (byte) 0x56,
    (byte) 0xA0,
    (byte) 0xB8,
    (byte) 0xEA,
    (byte) 0x67,
    (byte) 0xD1,
    (byte) 0x1C,
    (byte) 0x3E,
    (byte) 0x36,
    (byte) 0xFD
  };

  public static final V0DiscoveryCredential V0_CRED =
      new V0DiscoveryCredential(V0_KEY_SEED, V0_IDENTITY_TOKEN_HMAC);

  public static final byte[] V0_PRIVATE = {
    0x04, // adv header
    0x22,
    0x22, // salt
    (byte) 0xD8,
    (byte) 0x22,
    (byte) 0x12,
    (byte) 0xEF,
    (byte) 0x16,
    (byte) 0xDB,
    (byte) 0xF8,
    (byte) 0x72,
    (byte) 0xF2,
    (byte) 0xA3,
    (byte) 0xA7,
    (byte) 0xC0,
    (byte) 0xFA,
    (byte) 0x52,
    (byte) 0x48,
    (byte) 0xEC // ciphertext for metadata key & txpower DE
  };

  public static final byte[] V1_IDENTITY_TOKEN = {
    (byte) 0x58,
    (byte) 0x31,
    (byte) 0x00,
    (byte) 0x48,
    (byte) 0x11,
    (byte) 0xe4,
    (byte) 0xea,
    (byte) 0x43,
    (byte) 0xe9,
    (byte) 0x01,
    (byte) 0x76,
    (byte) 0x25,
    (byte) 0xd8,
    (byte) 0xaf,
    (byte) 0xd6,
    (byte) 0x92
  };

  public static final byte[] V1_KEY_SEED = {
    (byte) 0xc8,
    (byte) 0xdd,
    (byte) 0x01,
    (byte) 0x4d,
    (byte) 0x25,
    (byte) 0x01,
    (byte) 0xc0,
    (byte) 0xbf,
    (byte) 0x5b,
    (byte) 0x2a,
    (byte) 0x05,
    (byte) 0x48,
    (byte) 0x49,
    (byte) 0x8c,
    (byte) 0xe6,
    (byte) 0xbf,
    (byte) 0x48,
    (byte) 0x5b,
    (byte) 0x89,
    (byte) 0xb8,
    (byte) 0x47,
    (byte) 0x13,
    (byte) 0xcc,
    (byte) 0xdd,
    (byte) 0xa0,
    (byte) 0x18,
    (byte) 0xac,
    (byte) 0xd9,
    (byte) 0xef,
    (byte) 0x58,
    (byte) 0x9f,
    (byte) 0x76
  };

  public static final byte[] V1_MIC_SHORT_HMAC = {
    (byte) 0x09,
    (byte) 0x48,
    (byte) 0x4e,
    (byte) 0x8f,
    (byte) 0x39,
    (byte) 0xdc,
    (byte) 0x16,
    (byte) 0x27,
    (byte) 0x85,
    (byte) 0x0a,
    (byte) 0xea,
    (byte) 0xfc,
    (byte) 0x84,
    (byte) 0xf6,
    (byte) 0x43,
    (byte) 0x51,
    (byte) 0x62,
    (byte) 0x16,
    (byte) 0xf1,
    (byte) 0x8d,
    (byte) 0xda,
    (byte) 0xd3,
    (byte) 0xbc,
    (byte) 0xba,
    (byte) 0x43,
    (byte) 0xf1,
    (byte) 0x62,
    (byte) 0x4e,
    (byte) 0xa7,
    (byte) 0x09,
    (byte) 0xda,
    (byte) 0xde
  };

  public static final byte[] V1_MIC_LONG_HMAC = {
    (byte) 0xb9,
    (byte) 0x6a,
    (byte) 0xd2,
    (byte) 0x3e,
    (byte) 0x8e,
    (byte) 0x08,
    (byte) 0xe0,
    (byte) 0xf4,
    (byte) 0xe9,
    (byte) 0xba,
    (byte) 0xe9,
    (byte) 0xbb,
    (byte) 0x3d,
    (byte) 0xe3,
    (byte) 0x2f,
    (byte) 0xd1,
    (byte) 0x14,
    (byte) 0x3a,
    (byte) 0x51,
    (byte) 0x19,
    (byte) 0x54,
    (byte) 0xf8,
    (byte) 0x66,
    (byte) 0x9f,
    (byte) 0xf6,
    (byte) 0xdb,
    (byte) 0xf6,
    (byte) 0x03,
    (byte) 0xf7,
    (byte) 0x41,
    (byte) 0x20,
    (byte) 0xd7
  };

  public static final byte[] V1_SIG_HMAC = {
    (byte) 0xc4,
    (byte) 0x19,
    (byte) 0x6e,
    (byte) 0x84,
    (byte) 0x95,
    (byte) 0x3a,
    (byte) 0x8a,
    (byte) 0x97,
    (byte) 0xb9,
    (byte) 0xed,
    (byte) 0xf0,
    (byte) 0xba,
    (byte) 0xd2,
    (byte) 0x5d,
    (byte) 0xa4,
    (byte) 0x32,
    (byte) 0xb1,
    (byte) 0xf2,
    (byte) 0x1a,
    (byte) 0xf7,
    (byte) 0x7d,
    (byte) 0x95,
    (byte) 0x8f,
    (byte) 0xeb,
    (byte) 0x5f,
    (byte) 0xbe,
    (byte) 0xfd,
    (byte) 0x62,
    (byte) 0xa7,
    (byte) 0xc0,
    (byte) 0x16,
    (byte) 0x66
  };

  public static final byte[] V1_PUB_KEY = {
    (byte) 0x3c,
    (byte) 0x59,
    (byte) 0xd7,
    (byte) 0x30,
    (byte) 0x58,
    (byte) 0x8c,
    (byte) 0x45,
    (byte) 0x26,
    (byte) 0x7e,
    (byte) 0x52,
    (byte) 0x29,
    (byte) 0x54,
    (byte) 0xca,
    (byte) 0xc9,
    (byte) 0xcb,
    (byte) 0xca,
    (byte) 0x72,
    (byte) 0x94,
    (byte) 0x24,
    (byte) 0xd8,
    (byte) 0xf5,
    (byte) 0xa6,
    (byte) 0x1e,
    (byte) 0xcf,
    (byte) 0x04,
    (byte) 0x3e,
    (byte) 0x8f,
    (byte) 0x91,
    (byte) 0x81,
    (byte) 0x6d,
    (byte) 0x19,
    (byte) 0x74
  };

  public static final V1DiscoveryCredential V1_CRED =
      new V1DiscoveryCredential(
          V1_KEY_SEED, V1_MIC_SHORT_HMAC, V1_MIC_LONG_HMAC, V1_SIG_HMAC, V1_PUB_KEY);

  public static final byte[] V1_PRIVATE = {
    (byte) 0x20,
    (byte) 0x03,
    (byte) 0xfc,
    (byte) 0x32,
    (byte) 0xb7,
    (byte) 0x5d,
    (byte) 0xdd,
    (byte) 0x6a,
    (byte) 0xdb,
    (byte) 0xb0,
    (byte) 0x89,
    (byte) 0x7d,
    (byte) 0xb9,
    (byte) 0xcd,
    (byte) 0xa9,
    (byte) 0x6e,
    (byte) 0x73,
    (byte) 0x6d,
    (byte) 0x7a,
    (byte) 0xfc,
    (byte) 0xeb,
    (byte) 0x2b,
    (byte) 0x0c,
    (byte) 0x02,
    (byte) 0x3d,
    (byte) 0xc8,
    (byte) 0xfa,
    (byte) 0xc8,
    (byte) 0x78,
    (byte) 0x83,
    (byte) 0x56,
    (byte) 0xfa,
    (byte) 0x53,
    (byte) 0x11,
    (byte) 0x42,
    (byte) 0x08,
    (byte) 0x9e,
    (byte) 0xfe,
    (byte) 0x70,
    (byte) 0xd0,
    (byte) 0x68,
    (byte) 0x6c,
    (byte) 0x7c,
    (byte) 0x29,
    (byte) 0x86,
    (byte) 0xd6,
    (byte) 0x76,
    (byte) 0x2b,
    (byte) 0x03,
    (byte) 0xa4,
    (byte) 0xc7,
    (byte) 0x47,
    (byte) 0x5c,
    (byte) 0x41,
    (byte) 0x9d,
    (byte) 0x21,
    (byte) 0x15,
    (byte) 0x54,
    (byte) 0x89,
    (byte) 0x43,
    (byte) 0x32,
    (byte) 0x44,
    (byte) 0x47,
    (byte) 0x34,
    (byte) 0xd7,
    (byte) 0xbd,
    (byte) 0x4f,
    (byte) 0x38,
    (byte) 0x83,
    (byte) 0x74,
    (byte) 0xe4,
    (byte) 0xdb,
    (byte) 0xcf,
    (byte) 0xfe,
    (byte) 0xe4,
    (byte) 0x7a,
    (byte) 0xae,
    (byte) 0xa8,
    (byte) 0xe2,
    (byte) 0xf5,
    (byte) 0x69,
    (byte) 0xb8,
    (byte) 0x42,
    (byte) 0xf5,
    (byte) 0x67,
    (byte) 0x7a,
    (byte) 0x34,
    (byte) 0x6d,
    (byte) 0x86,
    (byte) 0x8b,
    (byte) 0x4c,
    (byte) 0xa9,
    (byte) 0x7f,
    (byte) 0x45,
    (byte) 0x1c,
    (byte) 0x37,
    (byte) 0xf1,
    (byte) 0x6e,
    (byte) 0xfc,
    (byte) 0xae,
    (byte) 0xc6
  };
}
