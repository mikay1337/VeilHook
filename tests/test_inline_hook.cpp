#define SNITCH_IMPLEMENTATION
#include <snitch/snitch.hpp>
#include <VeilHook/inline_hook.hpp>
#include <thread>

__declspec(noinline) auto sum(int x, int y) -> int 
{ 
    return x + y; 
}

__declspec(noinline) auto hooked_sum([[maybe_unused]]int x, [[maybe_unused]]int y) -> int
{ 
    return 1337;
}


TEST_CASE("Basic Inline Hook", "[InlineHook]")  // NOLINT
{
  auto hook_result = VeilHook::InlineHook::Create(
      VeilHook::detail::address_cast<std::uintptr_t>(&sum),
      VeilHook::detail::address_cast<std::uintptr_t>(&hooked_sum));
   REQUIRE(hook_result.has_value());
   VeilHook::InlineHook hook = std::move(hook_result.value());
   REQUIRE((sum(1, 1) == 2));
   REQUIRE(hook.Enable().has_value());
   REQUIRE(sum(1, 1) == 1337);
   REQUIRE(hook.Call<int>(1, 1) == 2);
   REQUIRE(hook.Disable().has_value());
   REQUIRE((sum(1, 1) == 2));
   REQUIRE(hook.Call<int>(1, 1) == 2);
}

TEST_CASE("Multithread", "[InlineHook]")  // NOLINT
{
  REQUIRE(sum(1, 1) == 2);
  int idx = 0;
  std::thread t([&] {
        idx = 1;
        while (sum(1, 1) != 1337) { }
        idx = 2;
        while (sum(1, 1) != 2) {}
        idx = 3;
      });
  auto hook_result = VeilHook::InlineHook::Create(
      VeilHook::detail::address_cast<std::uintptr_t>(&sum),
      VeilHook::detail::address_cast<std::uintptr_t>(&hooked_sum));
  REQUIRE(hook_result.has_value());
  VeilHook::InlineHook hook = std::move(hook_result.value());
  while (idx != 1) { Sleep(1); }
  REQUIRE(hook.Enable().has_value());
  while (idx != 2) { Sleep(1); }
  REQUIRE(hook.Disable().has_value());
  while (idx != 3) { Sleep(1); }

  t.join();
}