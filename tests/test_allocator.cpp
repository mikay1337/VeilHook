#define SNITCH_IMPLEMENTATION
#include <snitch/snitch.hpp>

#include <VeilHook/allocator.hpp>

TEST_CASE("Basic Test", "[Allocator]")  // NOLINT
{
    auto p = VeilHook::Allocator::Get()->Allocate(1024);
    REQUIRE(p.has_value());
    REQUIRE((p.value().address() != 0));
    REQUIRE((p.value().size() == 1024));
    p->free();
}

TEST_CASE("Logic Test", "[Allocator]")  // NOLINT
{
  using namespace VeilHook;
  auto VA = Allocator::Get();
  Allocation base_alloc = std::move(VA->Allocate(16).value());
  Allocation a2 = std::move(VA->Allocate(16).value());
  REQUIRE((base_alloc.address() + 16) == a2.address());
  Allocation a3 = std::move(VA->Allocate(32).value());
  REQUIRE((base_alloc.address() + 32) == a3.address());
  a2.free();
  Allocation a4 = std::move(VA->Allocate(32).value());
  REQUIRE((base_alloc.address() + 64) == a4.address());
  a3.free();
  Allocation a5 = std::move(VA->Allocate(32 + 16).value());
  REQUIRE((base_alloc.address() + 16) == a5.address());

  




}