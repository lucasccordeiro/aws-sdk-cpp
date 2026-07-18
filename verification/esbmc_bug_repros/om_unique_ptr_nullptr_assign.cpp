/**
 * ESBMC reproducer: std::unique_ptr is missing the nullptr_t assignment and
 * the (non-explicit) nullptr_t constructor required by [unique.ptr.single].
 *
 *   $ esbmc --std c++11 om_unique_ptr_nullptr_assign.cpp
 *   error: no viable overloaded '='
 *
 *   $ g++ -std=c++11 -c om_unique_ptr_nullptr_assign.cpp    # accepted
 *
 * NOTE: reproduces against a STOCK ESBMC 8.4.0. A build carrying the proposed
 * patch to src/cpp/library/memory reports VERIFICATION SUCCESSFUL instead --
 * that is the fix working, not the reproducer rotting.
 *
 * ESBMC version 8.4.0 64-bit x86_64 linux
 */
#include <memory>
int main() {
  std::unique_ptr<int> p(new int(1));
  p = nullptr;                 // [unique.ptr.single.asgn] p5
  return p ? 1 : 0;
}
