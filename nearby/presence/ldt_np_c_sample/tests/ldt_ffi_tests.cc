// Copyright 2022 Google LLC
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

#include <gtest/gtest.h>
#include <json/json.h>

extern "C" {
#include "np_ldt.h"
}

#include <algorithm>
#include <fstream>

// TODO: get multi threaded tests working on windows
#ifndef _WIN32
#include <pthread.h>
#endif

#ifdef LDT_TEST_VECTORS
static const char *PATH_TO_DATA_FILE = LDT_TEST_VECTORS;
#else
static const char *PATH_TO_DATA_FILE = "np_adv_test_vectors.json";
#endif
static const uint8_t KEY_SEED_BYTES[] = {
    204, 219, 36, 137, 233, 252, 172, 66,  179, 147, 72, 184, 148, 30, 209, 154,
    29,  54,  14, 117, 224, 152, 200, 193, 94,  107, 28, 194, 182, 32, 205, 57};
static const uint8_t KNOWN_HMAC_BYTES[] = {
    223, 185, 10,  31,  155, 31, 226, 141, 24,  187, 204,
    165, 34,  64,  181, 204, 44, 203, 95,  141, 82,  137,
    163, 203, 100, 235, 53,  65, 202, 97,  75,  180};
static const uint8_t TEST_DATA_BYTES[] = {205, 104, 63, 225, 161, 209, 248,
                                          70,  84,  61, 10,  19,  212, 174,
                                          164, 0,   64, 200, 214, 123};

static NpLdtSalt salt = {{12, 15}};

static NpLdtEncryptHandle create_enc_handle_from_test_key() {
  NpLdtKeySeed key_seed;
  memcpy(key_seed.bytes, KEY_SEED_BYTES, 32);

  return NpLdtEncryptCreate(key_seed);
}

static NpLdtDecryptHandle create_dec_handle_from_test_key() {
  NpLdtKeySeed key_seed;
  memcpy(key_seed.bytes, KEY_SEED_BYTES, 32);

  NpMetadataKeyHmac known_hmac;
  memcpy(known_hmac.bytes, KNOWN_HMAC_BYTES, 32);

  return NpLdtDecryptCreate(key_seed, known_hmac);
}

static void hex_string_to_bytes(const char *hexString, uint8_t *out,
                                size_t len) {
  for (size_t count = 0; count < len; count++) {
    sscanf(hexString, "%2hhx", &out[count]); // NOLINT(cert-err34-c)
    hexString += 2;
  }
}

static void bytes_to_hex_string(uint8_t *data, char *out, size_t len) {
  std::stringstream ss;
  ss << std::hex;
  for (size_t i = 0; i < len; ++i)
    ss << std::setw(2) << std::setfill('0') << (int)data[i];

  std::string result = ss.str();
  transform(result.begin(), result.end(), result.begin(), ::toupper);
  strcpy(out, result.c_str());
}

// Run through JSON data with test cases generated by Rust tests.
// Using generated data for now because the C layer does not have the ability
// to generate the ldt_key and hmac_key from a key_seed, this is an
// implementation detail of the rust ldt library
TEST(LdtFfiTests, TestJsonData) {
  Json::Value root;
  Json::Reader reader;
  std::ifstream test(PATH_TO_DATA_FILE);
  bool parsingSuccessful = reader.parse(test, root, false);
  if (!parsingSuccessful) {
    std::cout << reader.getFormattedErrorMessages() << "\n";
  }
  ASSERT_TRUE(root.size() == 1000);

  for (const auto &v : root) {
    auto key_seed = v["key_seed"].asCString();
    auto metadata_key_hmac = v["metadata_key_hmac"].asCString();
    auto adv_salt = v["adv_salt"].asCString();
    auto plaintext = v["plaintext"].asCString();
    auto ciphertext = v["ciphertext"].asCString();

    NpLdtKeySeed np_key_seed;
    auto len = strlen(key_seed) / 2;
    hex_string_to_bytes(key_seed, np_key_seed.bytes, len);
    ASSERT_EQ(len, 32);

    NpMetadataKeyHmac known_hmac;
    len = strlen(metadata_key_hmac) / 2;
    hex_string_to_bytes(metadata_key_hmac, known_hmac.bytes, len);
    ASSERT_EQ(len, 32);

    NpLdtEncryptHandle enc_handle = NpLdtEncryptCreate(np_key_seed);
    ASSERT_TRUE(enc_handle.handle != 0);

    NpLdtSalt salt_data;
    len = strlen(adv_salt) / 2;
    hex_string_to_bytes(adv_salt, salt_data.bytes, len);
    ASSERT_TRUE(len == 2);

    len = strlen(plaintext) / 2;
    auto buffer = (uint8_t *)malloc(len);
    hex_string_to_bytes(plaintext, buffer, len);
    NP_LDT_RESULT result = NpLdtEncrypt(enc_handle, buffer, len, salt_data);
    ASSERT_EQ(result, NP_LDT_SUCCESS);

    char *output = (char *)malloc(strlen(plaintext) + 1);
    bytes_to_hex_string(buffer, output, len);
    ASSERT_EQ(strcmp(output, ciphertext), 0);

    NpLdtDecryptHandle dec_handle = NpLdtDecryptCreate(np_key_seed, known_hmac);
    ASSERT_TRUE(dec_handle.handle != 0);

    result = NpLdtDecryptAndVerify(dec_handle, buffer, len, salt_data);
    ASSERT_EQ(result, NP_LDT_SUCCESS);

    result = NpLdtEncryptClose(enc_handle);
    ASSERT_EQ(result, NP_LDT_SUCCESS);

    result = NpLdtDecryptClose(dec_handle);
    ASSERT_EQ(result, NP_LDT_SUCCESS);

    bytes_to_hex_string(buffer, output, len);
    ASSERT_EQ(strcmp(output, plaintext), 0);
    free(buffer);
    free(output);
  }
  test.close();
}

TEST(LdtFfiTests, TestValidLength) {
  auto plaintext = (uint8_t *)malloc(20 * sizeof(uint8_t));
  memcpy(plaintext, TEST_DATA_BYTES, 20);

  NpLdtEncryptHandle enc_handle = create_enc_handle_from_test_key();
  ASSERT_TRUE(enc_handle.handle != 0);

  NP_LDT_RESULT result = NpLdtEncrypt(enc_handle, plaintext, 20, salt);
  ASSERT_EQ(result, NP_LDT_SUCCESS);

  NpLdtDecryptHandle dec_handle = create_dec_handle_from_test_key();

  result = NpLdtDecryptAndVerify(dec_handle, plaintext, 20, salt);
  ASSERT_EQ(result, NP_LDT_SUCCESS);
  free(plaintext);
}

TEST(LdtFfiTests, TestEncryptInvalidLength) {
  auto plaintext = (uint8_t *)malloc(32 * sizeof(uint8_t));
  memcpy(plaintext, TEST_DATA_BYTES, 20);

  NpLdtEncryptHandle enc_handle = create_enc_handle_from_test_key();
  ASSERT_TRUE(enc_handle.handle != 0);

  NP_LDT_RESULT result = NpLdtEncrypt(enc_handle, plaintext, 32, salt);
  ASSERT_EQ(result, NP_LDT_ERROR_INVALID_LENGTH);

  result = NpLdtEncrypt(enc_handle, plaintext, 15, salt);
  ASSERT_EQ(result, NP_LDT_ERROR_INVALID_LENGTH);
  free(plaintext);
}

TEST(LdtFfiTests, TestDecryptInvalidLength) {
  auto plaintext = (uint8_t *)malloc(32 * sizeof(uint8_t));
  memcpy(plaintext, TEST_DATA_BYTES, 20);

  NpLdtDecryptHandle dec_handle = create_dec_handle_from_test_key();
  ASSERT_TRUE(dec_handle.handle != 0);

  NP_LDT_RESULT result = NpLdtDecryptAndVerify(dec_handle, plaintext, 32, salt);
  ASSERT_EQ(result, NP_LDT_ERROR_INVALID_LENGTH);

  result = NpLdtDecryptAndVerify(dec_handle, plaintext, 15, salt);
  ASSERT_EQ(result, NP_LDT_ERROR_INVALID_LENGTH);
  free(plaintext);
}

// We want to make sure no decryption is performed when the hmac is invalid
TEST(LdtFfiTests, TestDecryptMacMismatch) {
  char test_text[] = "this text should not change!";
  auto plaintext = (uint8_t *)malloc(30 * sizeof(char));
  memcpy(plaintext, test_text, 29);

  NpLdtDecryptHandle dec_handle = create_dec_handle_from_test_key();
  ASSERT_TRUE(dec_handle.handle != 0);

  NP_LDT_RESULT result = NpLdtDecryptAndVerify(dec_handle, plaintext, 24, salt);
  ASSERT_EQ(result, NP_LDT_ERROR_MAC_MISMATCH);

  ASSERT_EQ(strcmp((char *)plaintext, test_text), 0);
  free(plaintext);
}

TEST(LdtFfiTests, TestInvalidHandle) {
  auto plaintext = (uint8_t *)malloc(20 * sizeof(uint8_t));
  memcpy(plaintext, TEST_DATA_BYTES, 20);

  NP_LDT_RESULT result =
      NpLdtEncrypt(NpLdtEncryptHandle{1234}, plaintext, 20, salt);
  ASSERT_EQ(result, NP_LDT_INVALID_HANDLE);

  result = NpLdtDecryptAndVerify(NpLdtDecryptHandle{1234}, plaintext, 20, salt);
  ASSERT_EQ(result, NP_LDT_INVALID_HANDLE);
  free(plaintext);

  result = NpLdtEncryptClose(NpLdtEncryptHandle{1234});
  ASSERT_EQ(result, NP_LDT_INVALID_HANDLE);

  result = NpLdtDecryptClose(NpLdtDecryptHandle{1234});
  ASSERT_EQ(result, NP_LDT_INVALID_HANDLE);
}

#ifndef _WIN32
pthread_mutex_t my_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

void *worker_thread(void *arg) {
  (void)arg;
  pthread_mutex_lock(&my_mutex);

  pthread_cond_wait(&cond, &my_mutex);
  pthread_mutex_unlock(&my_mutex);

  auto plaintext = (uint8_t *)malloc(20 * sizeof(uint8_t));
  memcpy(plaintext, TEST_DATA_BYTES, 20);

  NpLdtEncryptHandle enc_handle = create_enc_handle_from_test_key();
  if (enc_handle.handle == 0) {
    printf("Error creating handle in thread!");
    free(plaintext);
    exit(2);
  }

  NP_LDT_RESULT result = NpLdtEncrypt(enc_handle, plaintext, 20, salt);
  if (result != NP_LDT_SUCCESS) {
    printf("Error in encrypt in thread!");
    free(plaintext);
    exit(2);
  }

  NpLdtDecryptHandle dec_handle = create_dec_handle_from_test_key();
  if (dec_handle.handle == 0) {
    printf("Error creating handle in thread!");
    free(plaintext);
    exit(2);
  }
  result = NpLdtDecryptAndVerify(dec_handle, plaintext, 20, salt);
  if (result != NP_LDT_SUCCESS) {
    printf("Error in decrypt in thread!");
    free(plaintext);
    exit(2);
  }

  free(plaintext);
  pthread_exit(nullptr);
}

TEST(LdtFfiTests, MultiThreadedTests) {
  int i, num_threads = 100;
  pthread_t tid[num_threads];
  memset(tid, 0, num_threads * sizeof(pthread_t));

  // Create the threads
  for (i = 0; i < num_threads; i++)
    ASSERT_EQ(pthread_create(&tid[i], nullptr, worker_thread, (void *)&tid[i]),
              0);

  // give time for all threads to lock
  sleep(1);

  // unleash the threads!
  pthread_cond_broadcast(&cond);

  // Wait for them all to finish and check the status
  for (i = 0; i < num_threads; i++)
    ASSERT_EQ(pthread_join(tid[i], nullptr), 0);
}
#endif