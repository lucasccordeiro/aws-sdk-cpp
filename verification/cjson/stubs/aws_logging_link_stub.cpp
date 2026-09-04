/**
 * Verification-only substitute for the logger registry in
 * source/utils/logging/AWSLogging.cpp. A null log system is the state of a
 * process that never called Aws::Utils::Logging::InitializeAWSLogging, which is
 * what AWS_LOGSTREAM_* macros test for before formatting (LogMacros.h:55).
 *
 * That guard is J-1's condition in miniature: the marshaller's WriteReadable
 * call sits inside AWS_LOGSTREAM_TRACE, so a null log system is also the state
 * in which the SDK does not make it. The witnesses call the writers directly and
 * do not depend on the log level; the patched writers log through this stub.
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
