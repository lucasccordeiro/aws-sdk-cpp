/**
 * ESBMC reproducer, minimal: placement new with no initializer.
 *
 * This is the self-contained root-cause reduction of esbmc/esbmc#6184 -- no AWS
 * headers, no shim, no -I flags:
 *
 *   $ esbmc --std c++11 esbmc_bug_repros/placement_new_no_init.cpp
 *   Converting
 *   Generating GOTO Program
 *   ERROR:
 *   migrate expr failed
 *   <core dumped>
 *
 * WHY: `new (p) T;` for a non-class T default-initializes, which for such a
 * type performs no initialization at all ([dcl.init.general]). Clang therefore
 * attaches no initializer child to the CXXNewExpr, and ESBMC builds a "comma"
 * expression with a single operand. clang_c_adjust::adjust_comma
 * (src/clang-c-frontend/clang_c_adjust_expr.cpp:1589) then does
 *
 *     expr.type() = expr.op1().type();
 *
 * unguarded -- reading one past the end of a one-element operand vector. The
 * garbage irept that comes back is what the earlier gdb session mistook for a
 * use-after-free of irept::dt: ref_count == 0, a mutex with an invalid __kind,
 * and an _M_color enum holding a pointer are all just out-of-bounds bytes, not
 * recycled memory. That also explains the run-to-run variation in the glibc
 * abort message.
 *
 * The differential is clean:
 *
 *     new (p) int;    ->  crash          (no initializer child)
 *     new (p) int();  ->  VERIFICATION SUCCESSFUL
 *
 * aws-sdk-cpp reaches this through Aws::NewArray, whose loop body is
 * `new (base + i) T;` -- see crash_goto_convert_array.cpp for the original
 * end-to-end trigger via Aws::Utils::ByteBuffer.
 *
 * Requires esbmc/esbmc#6190 only for the AWS-header path, not for this file.
 */
#include <new>
#include <cassert>

int main()
{
  /* Scalar, no initializer -- the trigger. */
  alignas(int) char ibuf[sizeof(int)];
  int *p = new (ibuf) int;
  assert((void *)p == (void *)ibuf); /* result aliases the placement address */
  *p = 42;                           /* default-init leaves it indeterminate */
  assert(*p == 42);

  /* unsigned char: the aws-sdk-cpp ByteBuffer element type from #6184. */
  unsigned char cbuf[1];
  unsigned char *q = new (cbuf) unsigned char;
  *q = 7;
  assert(*q == 7);

  /* The Aws::NewArray shape: `new (base + i) T;` in a loop. */
  alignas(int) char abuf[3 * sizeof(int)];
  int *base = (int *)abuf;
  for (int i = 0; i < 3; ++i)
  {
    int *e = new (base + i) int;
    *e = i;
  }
  assert(base[0] == 0);
  assert(base[1] == 1);
  assert(base[2] == 2);

  return 0;
}
