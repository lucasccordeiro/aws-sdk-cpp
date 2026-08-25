/**
 * Definitions for aws/core/platform/Time.h, whose real implementations live in
 * the per-platform source/platform/{linux-shared,windows,android}/Time.cpp that
 * this module does not vendor.
 *
 * These are the POSIX bodies the linux-shared implementation uses, so the
 * behaviour matches the platform build the harness runs on. Nothing here is
 * under test -- the target is the DateParser state machines in
 * DateTimeCommon.cpp -- but ConvertTimestampToGmtStruct calls TimeGM on the
 * parsed tm, so it must convert rather than merely link.
 */

#include <aws/core/platform/Time.h>

#include <ctime>

namespace Aws
{
namespace Time
{

time_t TimeGM(tm *const t)
{
  return timegm(t);
}

void LocalTime(tm *t, std::time_t time)
{
  localtime_r(&time, t);
}

void GMTime(tm *t, std::time_t time)
{
  gmtime_r(&time, t);
}

} // namespace Time
} // namespace Aws
