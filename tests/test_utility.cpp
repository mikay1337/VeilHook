#define SNITCH_IMPLEMENTATION
#include <snitch/snitch.hpp>

#include <VeilHook/utility.hpp>

TEST_CASE("Utility") // NOLINT
{
    auto result = VeilHook::Impl::vm_alloc(0, 1024, VeilHook::Impl::VM_ACCESS_R);
    REQUIRE(result.has_value());
    VeilHook::Impl::VMAccess old_access = 0;
    REQUIRE(VeilHook::Impl::vm_protect(result.value(), 1024, VeilHook::Impl::VM_ACCESS_RWX, old_access));

    auto query = VeilHook::Impl::vm_query(result.value());
    REQUIRE(query);
    REQUIRE((query.value().access == VeilHook::Impl::VM_ACCESS_RWX));

    VeilHook::Impl::vm_free(result.value());
}