/**
 * ESBMC reproducer: <type_traits> operational model is missing std::is_class,
 * std::is_polymorphic and std::is_trivially_default_constructible (also
 * std::is_trivially_destructible, not exercised here).
 *
 *   $ esbmc --std c++11 om_missing_type_traits.cpp
 *   error: no member named 'is_class' in namespace 'std'
 *   error: no member named 'is_polymorphic' in namespace 'std'
 *   error: no member named 'is_trivially_default_constructible' in namespace 'std'
 *
 *   $ g++ -std=c++11 -c om_missing_type_traits.cpp          # accepted
 *
 * ESBMC's clang frontend already accepts the corresponding __is_class /
 * __is_polymorphic / __is_trivially_constructible builtins, so each trait is a
 * one-line addition to src/cpp/library/type_traits.
 *
 * ESBMC version 8.4.0 64-bit x86_64 linux
 */
#include <type_traits>

struct Plain { int x; };
struct Poly  { virtual ~Poly() {} };

static_assert(std::is_class<Plain>::value, "is_class");
static_assert(std::is_polymorphic<Poly>::value, "is_polymorphic");
static_assert(std::is_trivially_default_constructible<Plain>::value,
              "is_trivially_default_constructible");

int main() { return 0; }
