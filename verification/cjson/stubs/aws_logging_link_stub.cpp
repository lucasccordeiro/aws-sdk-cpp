/**
 * Verification-only substitute for the logger registry in
 * source/utils/logging/AWSLogging.cpp. A null log system is the state of a
 * process that never called Aws::Utils::Logging::InitializeAWSLogging, which is
 * what AWS_LOGSTREAM_* macros test for before formatting (LogMacros.h:19).
 *
 * SimpleStreamBuf reaches one such macro, on GrowBuffer's nullptr branch
 * (SimpleStreamBuf.cpp:133); nothing here decides whether that branch is taken.
 */

#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/core/utils/logging/LogSystemInterface.h>

namespace Aws
{
namespace Utils
{
namespace Logging
{
LogSystemInterface *GetLogSystem()
{
  return nullptr;
}
} // namespace Logging
} // namespace Utils
} // namespace Aws
