#include "VeilHook/inline_hook.hpp"
#include "VeilHook/error.hpp"

#include <Zydis/Zydis.h>
#include <expected>

namespace VeilHook
{

#if defined(VH_COMPILER_MSVC)
#pragma pack(push, 1)
#endif
struct VH_PACKED JmpE9
{
  std::uint8_t opcode{0xE9};
  std::int32_t offset{0};
};
#if defined(VH_ARCH_X86_64)
struct VH_PACKED JmpFF
{
  std::uint8_t opcode{0xFF};
  std::uint8_t opcode2{0x25};
  std::int32_t offset{0};
};
struct TrampolineEpilogueE9
{
  JmpE9 jmp_to_original{};
  JmpFF jmp_to_destination{};
  uint64_t destination_address{};
};
struct TrampolineEpilogueFF
{
  JmpFF jmp_to_original{};
  uint64_t original_address{};
};
#elif defined(VH_ARCH_X86_32)
struct VH_PACKED TrampolineEpilogueE9
{
  JmpE9 jmp_to_original{};
  JmpE9 jmp_to_destionation{};
};
#endif

#if defined(VH_COMPILER_MSVC)
#pragma pack(pop)
#endif

namespace Impl
{

auto make_jmp_e9(std::uintptr_t src, std::uintptr_t dest) -> JmpE9
{
  JmpE9 jmp{};
  jmp.offset = static_cast<std::int32_t>(dest - src - sizeof(jmp));
  return jmp;
}

auto make_jmp_ff(std::uintptr_t src, std::uintptr_t dest, std::uintptr_t data)
    -> JmpFF
{
  JmpFF jmp{};
  jmp.offset = static_cast<std::int32_t>(data - src - sizeof(jmp));
  detail::store(data, dest); //NOLINT
  return jmp;
}

auto emit_jmp_e9(std::uintptr_t src, std::uintptr_t dest,
                 std::size_t size = sizeof(JmpE9)) -> std::expected<void, Error>
{
  if (size < sizeof(JmpE9)) { return std::unexpected(Error::NotEnoughSpace); }
  if (size > sizeof(JmpE9)) { detail::fill(src, size, 0xCC); }
  detail::store(src, make_jmp_e9(src, dest));
  return {};
}

auto emit_jmp_ff(std::uintptr_t src, std::uintptr_t dest, std::uintptr_t data,
                 std::size_t size = sizeof(JmpFF)) -> std::expected<void, Error>
{
  if (size < sizeof(JmpFF)) { return std::unexpected(Error::NotEnoughSpace); }
  if (size > sizeof(JmpFF)) { detail::fill(src, size, 0xCC); }
  detail::store(src, make_jmp_ff(src, dest, data));
  return {};
}

auto decode(ZydisDecodedInstruction& ix, std::uintptr_t address) -> bool
{
  ZydisDecoder decoder{};
#if defined(VH_ARCH_X86_64)
  auto status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                                 ZYDIS_STACK_WIDTH_64);
#elif defined(VH_ARCH_X86_32)
  auto status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32,
                                 ZYDIS_STACK_WIDTH_32);
#endif
  if (ZYAN_FAILED(status)) { return false; }
  return ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
      &decoder, nullptr, detail::address_cast<void*>(address), 15, &ix));
}

}  // namespace Impl

InlineHook::InlineHook(InlineHook&& other) noexcept
{
  *this = std::move(other);
}

auto InlineHook::operator=(InlineHook&& other) noexcept -> InlineHook&
{
  if (this != &other)
  {
    std::scoped_lock lock(mutex_, other.mutex_);
    target_ = other.target_;
    destination_ = other.destination_;
    trampoline_ = std::move(other.trampoline_);
    original_bytes_ = other.original_bytes_;
    original_bytes_size_ = other.original_bytes_size_;
    type_ = other.type_;
    enabled_ = other.enabled_;

    other.target_ = 0;
    other.destination_ = 0;
    other.trampoline_ = nullptr;
    other.original_bytes_size_ = 0;
    other.type_ = Type::None;
    other.enabled_ = false;
  }

  return *this;
}

auto InlineHook::Create(const std::shared_ptr<Allocator>& allocator,
                        std::uintptr_t target, std::uintptr_t destination)
    -> std::expected<InlineHook, Error>
{
  if (not allocator) { return std::unexpected(Error::Allocate); }
  InlineHook hook{};
  if (auto err = hook._setup(allocator, target, destination); not err)
  {
    return std::unexpected(err.error());
  }
  return hook;
}

auto InlineHook::_setup(const std::shared_ptr<Allocator>& allocator,
                        std::uintptr_t target, std::uintptr_t destination)
    -> std::expected<void, Error>
{
  target_ = target;
  destination_ = destination;
  if (auto e9_result = _e9_hook(allocator); not e9_result)
  {
#if defined(VH_ARCH_X86_64)
    return _ff_hook(allocator);
#elif defined(VH_ARCH_X86_32)
    return e9_result;
#endif
  }

  return {};
}

auto InlineHook::_e9_hook(const std::shared_ptr<Allocator>& allocator)
    -> std::expected<void, Error>
{
  std::size_t trampoline_size = sizeof(TrampolineEpilogueE9);

  std::vector<std::uintptr_t> desired_addresses{target_};
  ZydisDecodedInstruction ix{};

  for (auto ip = target_; ip < target_ + sizeof(JmpE9); ip += ix.length)
  {
    if (not Impl::decode(ix, ip))
    {
      return std::unexpected(Error::FailedDecodeInstruction);
    }

    trampoline_size += ix.length;
    std::copy_n(detail::address_cast<std::uint8_t*>(ip), ix.length,
                original_bytes_.data() + original_bytes_size_);
    original_bytes_size_ += ix.length;

    const auto is_rel = (ix.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;
    if (is_rel)
    {
      if (ix.raw.disp.size == 32)
      {
        const auto target_address = ip + ix.length + ix.raw.disp.value;
        desired_addresses.push_back(target_address);
      }
      else if (ix.raw.imm[0].size == 32)
      {
        const auto target_address = ip + ix.length + ix.raw.imm[0].value.s;
        desired_addresses.push_back(target_address);
      }
      else if (ix.meta.category == ZYDIS_CATEGORY_COND_BR &&
               ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT)
      {
        const auto target_address = ip + ix.length + ix.raw.imm[0].value.s;
        desired_addresses.push_back(target_address);
        trampoline_size += 4;
      }
      else if (ix.meta.category == ZYDIS_CATEGORY_UNCOND_BR and
               ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT)
      {
        const auto target_address = ip + ix.length + ix.raw.imm[0].value.s;
        desired_addresses.push_back(target_address);
        trampoline_size += 3;
      }
      else { return std::unexpected(Error::UnsupportedInstruction); }
    }
  }

  auto trampoline_allocation =
      allocator->Allocate(desired_addresses, trampoline_size);
  if (not trampoline_allocation)
  {
    return std::unexpected(Error::BadAllocation);
  }
  trampoline_ = std::make_unique<Allocation>(std::move(*trampoline_allocation));

  for (auto ip = target_, tramp_ip = trampoline_->address();
       ip < target_ + original_bytes_size_; ip += ix.length)
  {
    if (not Impl::decode(ix, ip))
    {
      trampoline_ = nullptr;
      return  std::unexpected( Error::FailedDecodeInstruction);
    }

    const auto is_rel = (ix.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;

    if (is_rel and ix.raw.disp.size == 32)
    {
      detail::copy(ip, tramp_ip, ix.length);
      const auto target_address = ip + ix.length + ix.raw.disp.value;
      const auto new_disp = target_address - (tramp_ip + ix.length);
      detail::store(tramp_ip + ix.raw.imm[0].offset,
                  static_cast<std::int32_t>(new_disp));
      tramp_ip += ix.length;
    }
    else if (is_rel and ix.raw.imm[0].size == 32)
    {
      detail::copy(ip, tramp_ip, ix.length);
      const auto target_address = ip + ix.length + ix.raw.imm[0].value.s;
      const auto new_disp = target_address - (tramp_ip + ix.length);
      detail::store(tramp_ip + ix.raw.imm[0].offset,
                  static_cast<std::int32_t>(new_disp));
      tramp_ip += ix.length;
    }
    else if (ix.meta.category == ZYDIS_CATEGORY_COND_BR &&
             ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT)
    {
      const auto target_address = ip + ix.length + ix.raw.imm[0].value.s;
      auto new_disp = target_address - (tramp_ip + ix.length);
      if (target_address >= target_ &&
          target_address < target_ + original_bytes_size_)
      {
        new_disp = ix.raw.imm[0].value.s;
      }
      detail::store<std::uint8_t>(tramp_ip, 0x0F);
      detail::store<std::uint8_t>(tramp_ip + 1, 0x10 + ix.opcode);
      detail::store<std::uint8_t>(tramp_ip + 2, static_cast<std::int8_t>(new_disp));
      tramp_ip += 6;
    }
    else if (ix.meta.category == ZYDIS_CATEGORY_UNCOND_BR and
             ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT)
    {
      const auto target_address = ip + ix.length + ix.raw.imm[0].value.s;
      auto new_disp = target_address - (tramp_ip + 5);
      if (target_address >= target_ &&
          target_address < target_ + original_bytes_size_)
      {
        new_disp = ix.raw.imm[0].value.s;
      }
      detail::store<std::uint8_t>(tramp_ip, 0xE9);
      detail::store<std::uint8_t>(tramp_ip + 1, static_cast<std::int8_t>(new_disp));
      tramp_ip += 5;
    }
    else
    {
      detail::copy(ip, tramp_ip, ix.length);
      tramp_ip += ix.length;
    }
  }

  auto* trampoline_epilogue = detail::address_cast<TrampolineEpilogueE9*>(
      trampoline_->address() + trampoline_size - sizeof(TrampolineEpilogueE9));

  auto src = detail::address_cast<std::uintptr_t>(&trampoline_epilogue->jmp_to_original);
  auto dst = target_ + original_bytes_size_;

  if (auto result = Impl::emit_jmp_e9(src, dst); not result) { return result; }

  src = detail::address_cast<std::uintptr_t>(&trampoline_epilogue->jmp_to_destination);
  dst = destination_;

#if defined(VH_ARCH_X86_64)
  auto data = detail::address_cast<std::uintptr_t>(
      &trampoline_epilogue->destination_address);

  if (auto result = Impl::emit_jmp_ff(src, dst, data); not result) { return result; }
#elif defined(VH_ARCH_X86_32)
  if (auto result = Impl::emit_jmp_e9(src, dst); result) { return result; }
#endif

  type_ = Type::E9;
  return {};
}

auto InlineHook::_ff_hook(const std::shared_ptr<Allocator>& allocator)
    -> std::expected<void, Error>
{
  std::size_t trampoline_size = sizeof(TrampolineEpilogueFF);
  ZydisDecodedInstruction ix{};

  for (auto ip = target_; ip < target_ + sizeof(JmpFF); ip += ix.length)
  {
    if (not Impl::decode(ix, ip))
    {
      return std::unexpected(Error::FailedDecodeInstruction);
    }

    if ((ix.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0)
    {
      return std::unexpected(Error::IpRelativeInstructionOutOfRange);
    }

    detail::copy(ip, detail::address_cast<std::uintptr_t>(original_bytes_.data()),
               ix.length);
    original_bytes_size_ += ix.length;
    trampoline_size += ix.length;
  }

  auto trampoline_allocation = allocator->Allocate(trampoline_size);
  if (!trampoline_allocation) { return std::unexpected(Error::BadAllocation); }
  trampoline_ =
      std::make_unique<Allocation>(std::move(trampoline_allocation.value()));

  detail::copy(detail::address_cast<std::uintptr_t>(original_bytes_.data()),
             trampoline_->address(), original_bytes_size_);

  const auto* trampoline_epilogue = detail::address_cast<TrampolineEpilogueFF*>(
      trampoline_->address() + trampoline_size - sizeof(TrampolineEpilogueFF));

  auto src = detail::address_cast<std::uintptr_t>(
      &trampoline_epilogue->jmp_to_original);
  auto dst = target_ + original_bytes_size_;
  auto data = detail::address_cast<std::uintptr_t>(
      &trampoline_epilogue->original_address);

  if (auto result = Impl::emit_jmp_ff(src, dst, data); result)
  {
    return result;
  }
  type_ = Type::FF;
  return {};
}

__declspec(noinline) void find_me() noexcept { }

auto InlineHook::Enable() -> std::expected<void, Error>
{
  std::scoped_lock lock{mutex_};
  if (enabled_) { return {}; }

   Impl::VehManager::instance().Register(
       target_, target_ + original_bytes_size_,
       [target = target_, original_bytes_size = original_bytes_size_](
           PEXCEPTION_POINTERS info) -> LONG
       {
         auto* ctx = info->ContextRecord;
 #if defined(VH_ARCH_X86_64)
         auto& ip = ctx->Rip;
 #elif defined(VH_ARCH_X86_32)
         auto& ip = ctx->Eip;
 #endif

         for (int i{0}; i < original_bytes_size; ++i)
         {
           if (ip == target + 1)
           {
             ip = target;
             return EXCEPTION_CONTINUE_EXECUTION;
           }
         }
         return EXCEPTION_CONTINUE_SEARCH;
       });

   auto get_vm_access = [](std::uintptr_t target) -> Impl::VMAccess
      {
#if defined(VH_PLATFORM_WINDOWS)
     MEMORY_BASIC_INFORMATION find_me_mbi{};
     MEMORY_BASIC_INFORMATION target_mbi{};

     VirtualQuery(detail::address_cast<void*>(find_me), &find_me_mbi,
                  sizeof(find_me_mbi));
     VirtualQuery(detail::address_cast<void*>(target), &target_mbi,
                  sizeof(target_mbi));

     auto result = Impl::VM_ACCESS_RW;

     if (find_me_mbi.AllocationBase == target_mbi.AllocationBase)
     {
       result = Impl::VM_ACCESS_RWX;
     }
     else 
     { 
         auto si = Impl::get_system_info();
         auto target_page_start = detail::align_down(target, si.page_size);
         auto target_page_end = detail::align_up(target, si.page_size);
         auto vp_start = detail::address_cast(&VirtualProtect);
         auto vp_end = vp_start + 0x20;
         if (target_page_end >= vp_start && vp_end >= target_page_start)
         {
           result = Impl::VM_ACCESS_RWX;
         }
     }
     return result;
           #else
     return Impl::VM_ACCESS_RWX;
           #endif
      };

  Impl::VMProtect protect_target(target_, original_bytes_size_, get_vm_access(target_));

  if (type_ == Type::E9)
  {
    auto* trampoline_epilogue = detail::address_cast<TrampolineEpilogueE9*>(
        trampoline_->address() + trampoline_->size() - sizeof(TrampolineEpilogueE9));
    if (auto result = Impl::emit_jmp_e9(target_, detail::address_cast<std::uintptr_t>(&trampoline_epilogue->jmp_to_destination)); not result)
    {
      return result;
    }
  }
  if (type_ == Type::FF)
  {
    if (auto result =
            Impl::emit_jmp_ff(target_, trampoline_->address(),
                              target_ + sizeof(JmpFF), original_bytes_size_); not result)
    {
      return result;
    }
  }

  enabled_ = true;
  return {};
}

auto InlineHook::Disable() -> std::expected<void, Error>
{
  std::scoped_lock lock{mutex_};

  if (!enabled_) { return {}; }
  enabled_ = false;
  Impl::VMProtect protect_target(target_, original_bytes_size_,
                                 Impl::VM_ACCESS_RWX);
  detail::copy(detail::address_cast<std::uintptr_t>(original_bytes_.data()),
             target_, original_bytes_size_);

  Impl::VehManager::instance().Unregister(target_);

  return {};
}

InlineHook::~InlineHook() { _destroy(); }

void InlineHook::_destroy() noexcept
{
    [[maybe_unused]] auto result = Disable();
    std::scoped_lock lock{mutex_};

    if (!trampoline_) { return; }
    trampoline_->free();
}

};  // namespace VeilHook