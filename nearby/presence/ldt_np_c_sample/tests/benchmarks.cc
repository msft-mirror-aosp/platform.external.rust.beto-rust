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

#include <benchmark/benchmark.h>
#include <ctime>

#include "np_ldt.h"

using std::vector;
using std::tuple;

const int BLOCK_SIZE = 16;
const int LDT_PAYLOAD_MAX_LEN = 31;


static void generateRandomBytes(uint8_t* output, int len)
{
    srand(time(0));
    for(int i = 0; i < len; i++){
        output[i] = rand();
    }
}

class NpLdtFfiBenchmark : public benchmark::Fixture {
public:
    size_t payload_len;
    uint8_t* payload;
    NpLdtSalt* salt;
    vector<NpLdtHandle> handles;
    vector<tuple<NpLdtKeySeed*, NpMetadataKeyHmac*>> configs;

    void SetUp(const ::benchmark::State& state)
    {
        int num_ciphers = state.range(0);
        buildCiphers(num_ciphers);
        generatePayload();
        generateSalt();
    }

    void TearDown(const ::benchmark::State& state)
    {
        free(salt);
        free(payload);
        freeCiphers();
        freeConfigValues();

        handles.clear();
        configs.clear();
    }
private:
    void buildCiphers(int num_ciphers)
    {
        for(int i = 0; i < num_ciphers; i++)
        {
            NpLdtHandle handle = buildCipherFromRand();
            handles.push_back(handle);
        }
    }

    NpLdtHandle buildCipherFromRand()
    {
        NpLdtKeySeed* key_seed = (NpLdtKeySeed*) malloc(sizeof(NpLdtKeySeed));
        NpMetadataKeyHmac* known_hmac = (NpMetadataKeyHmac*) malloc(sizeof(NpMetadataKeyHmac));

        generateRandomBytes(key_seed->bytes, 32);
        generateRandomBytes(known_hmac->bytes, 32);

        configs.push_back(tuple<NpLdtKeySeed*, NpMetadataKeyHmac*>(key_seed, known_hmac));
        return NpLdtCreate(*key_seed, *known_hmac);
    }

    void generatePayload()
    {
        payload_len = randNumInRange(BLOCK_SIZE, LDT_PAYLOAD_MAX_LEN);
        payload = (uint8_t*) malloc(payload_len);
        generateRandomBytes(payload, payload_len);
    }

    int randNumInRange(int lower, int upper)
    {
        return rand()%(upper - lower + 1) + lower;
    }

    void generateSalt()
    {
        salt = (NpLdtSalt*) malloc(sizeof(NpLdtSalt));
        generateRandomBytes(salt->bytes, 2);
    }

    void freeCiphers()
    {
        for(NpLdtHandle handle : handles)
        {
            NpLdtClose(handle);
        }
    }

    void freeConfigValues()
    {
        for(tuple<NpLdtKeySeed*, NpMetadataKeyHmac*> values : configs)
        {
            free(std::get<0>(values));
            free(std::get<1>(values));
        }
    }
};

BENCHMARK_DEFINE_F(NpLdtFfiBenchmark, DecryptExistingCiphers)(benchmark::State& state)
{
    for (auto _ : state)
    {
        for(NpLdtHandle handle : handles)
        {
            NpLdtDecryptAndVerify(handle, payload, payload_len, *salt);
        }
    }
};

BENCHMARK_REGISTER_F(NpLdtFfiBenchmark, DecryptExistingCiphers)->RangeMultiplier(10)->Range(1, 1000);

BENCHMARK_DEFINE_F(NpLdtFfiBenchmark, DecryptFreshCiphers)(benchmark::State& state)
{
    for (auto _ : state)
    {
        for(tuple<NpLdtKeySeed*, NpMetadataKeyHmac*> values : configs)
        {
            NpLdtHandle handle = NpLdtCreate(*std::get<0>(values), *std::get<1>(values));
            NpLdtDecryptAndVerify(handle, payload, payload_len, *salt);
        }
    }
};

BENCHMARK_REGISTER_F(NpLdtFfiBenchmark, DecryptFreshCiphers)->RangeMultiplier(10)->Range(1, 1000);

BENCHMARK_MAIN();
