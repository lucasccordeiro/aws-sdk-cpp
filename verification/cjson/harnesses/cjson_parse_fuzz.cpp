/**
 * libFuzzer entry point for the SDK's vendored cJSON fork.
 *
 * Mirrors what Aws::Utils::Json::JsonValue does to a response body
 * (JsonSerializer.cpp:31 and :47): ParseWithOpts with require_null_terminated,
 * then -- for the round-trip leg -- print and re-parse, which is what
 * JsonValue::View::WriteCompact / WriteReadable do.
 *
 * Default allocation hooks are in force here. Aws::InitAPI does install cJSON
 * hooks (Aws.cpp:165-168), but they route to Aws::Malloc/Aws::Free, which fall
 * through to malloc/free with no memory system installed -- so the fuzzer sees
 * the same real heap allocations, with real redzones, that the SDK does.
 */
#include <aws/core/external/cjson/cJSON.h>

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    const std::string json(reinterpret_cast<const char*>(data), size);

    cJSON* doc = cJSON_AS4CPP_ParseWithOpts(json.c_str(), nullptr, 1 /* require_null_terminated */);
    if (doc == nullptr)
    {
        return 0;
    }

    if (char* compact = cJSON_AS4CPP_PrintUnformatted(doc))
    {
        if (cJSON* reparsed = cJSON_AS4CPP_Parse(compact))
        {
            cJSON_AS4CPP_Delete(reparsed);
        }
        cJSON_AS4CPP_free(compact);
    }

    if (char* pretty = cJSON_AS4CPP_Print(doc))
    {
        cJSON_AS4CPP_free(pretty);
    }

    cJSON_AS4CPP_Delete(doc);
    return 0;
}
