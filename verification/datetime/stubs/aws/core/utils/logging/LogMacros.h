/**
 * Stands in for aws/core/utils/logging/LogMacros.h.
 *
 * DateTimeCommon.cpp logs on three paths: the over-MAX_LEN rejection in each
 * parser, and the non-UTC branch of ConvertTimestampToGmtStruct. None of them
 * affect the arithmetic under test, and pulling in the real logging subsystem
 * would drag in the whole AWSLogging/LogSystemInterface tree. The macros keep
 * their argument in an unevaluated `sizeof` so the streamed expression is still
 * type-checked -- a log line that would not compile upstream will not compile
 * here either.
 *
 * Expands to a braced block, NOT a do/while: upstream invokes these macros with
 * no trailing semicolon (DateTimeCommon.cpp:432 and friends), so a form that
 * needs one fails to parse the statement that follows.
 */

#pragma once

#include <sstream>

#define AWS_UNREFERENCED_LOG(streamExpression)                                 \
  {                                                                            \
    (void)sizeof(std::stringstream() << streamExpression);                     \
  }

#define AWS_LOGSTREAM_TRACE(tag, streamExpression) AWS_UNREFERENCED_LOG(streamExpression)
#define AWS_LOGSTREAM_DEBUG(tag, streamExpression) AWS_UNREFERENCED_LOG(streamExpression)
#define AWS_LOGSTREAM_INFO(tag, streamExpression) AWS_UNREFERENCED_LOG(streamExpression)
#define AWS_LOGSTREAM_WARN(tag, streamExpression) AWS_UNREFERENCED_LOG(streamExpression)
#define AWS_LOGSTREAM_ERROR(tag, streamExpression) AWS_UNREFERENCED_LOG(streamExpression)
#define AWS_LOGSTREAM_FATAL(tag, streamExpression) AWS_UNREFERENCED_LOG(streamExpression)
