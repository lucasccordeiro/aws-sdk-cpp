/**
 * Verification stub for aws/core/utils/local/Random.h.
 *
 * Reproduces the one declaration UUID::PseudoRandomUUID names. Definition is a
 * link stub in stubs/aws_random_link_stub.cpp; unreached by the string ctor.
 */
#pragma once

#include <random>

namespace Aws
{
namespace Utils
{
std::mt19937::result_type GetRandomValue();
} // namespace Utils
} // namespace Aws
