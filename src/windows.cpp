#include <VeilHook/utility.hpp>
#include <algorithm>
#include <mutex>

namespace std
{
template <>
struct hash<VeilHook::Impl::VehEntry>
{
  auto operator()(const VeilHook::Impl::VehEntry& entry) const
      -> std::size_t
  {
    return std::hash<std::uintptr_t>{}(entry.start_address) ^
           (std::hash<std::uintptr_t>{}(entry.end_address) << 1);
  }
};
}  // namespace std

namespace VeilHook::Impl
{

void* VehManager::handle_ = nullptr;
std::mutex VehManager::mutex_;
std::unordered_set<VehEntry> VehManager::entries_;

auto VehManager::instance() -> VehManager&
{
  static VehManager instance;
  return instance;
}

VehManager::VehManager()
{
  std::scoped_lock lock(VehManager::mutex_);
  if (handle_ != nullptr) { return; }
  handle_ = AddVectoredExceptionHandler(1, _handler);
}

VehManager::~VehManager()
{
  std::scoped_lock lock(VehManager::mutex_);
  if (handle_ == nullptr) { return; }
  RemoveVectoredExceptionHandler(handle_);
}

void VehManager::Register(std::uintptr_t start_address,
                          std::uintptr_t end_address,
                          VehEntry::Callback callback)
{
  std::scoped_lock lock(mutex_);
  VehEntry entry{.start_address = start_address,
                 .end_address = end_address,
                 .callback = std::move(callback)};
  entries_.emplace(std::move(entry));
}
void VehManager::Unregister(std::uintptr_t address)
{
  std::scoped_lock lock(mutex_);
  auto it = std::ranges::find_if(entries_, [&](const VehEntry& entry)
                                 { return entry.start_address == address; });
  if (it != entries_.end()) { entries_.erase(it); }
}

auto VehManager::_handler(PEXCEPTION_POINTERS info) -> LONG
{
  std::scoped_lock<std::mutex> lock(VehManager::mutex_);
  DWORD code = info->ExceptionRecord->ExceptionCode;
#if defined(VH_ARCH_X86_64)
  std::uintptr_t ip = info->ContextRecord->Rip;
#else
  std::uintptr_t ip = info->ContextRecord->Eip;
#endif

  switch (code)
  {
    case 0xE06D7363: break;  // C++ exception
    case EXCEPTION_GUARD_PAGE:
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_BREAKPOINT:
    case EXCEPTION_SINGLE_STEP:
    {
      for (const auto& entry : entries_)
      {
        if ((entry.start_address <= ip) && (entry.end_address >= ip))
        {
          return entry.callback(info);
        }
      }
      break;
    }
    default: break;
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

auto get_system_info() -> SystemInfo
{
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  return {.page_size = info.dwPageSize,
          .granularity = info.dwAllocationGranularity,
          .min_address = detail::address_cast<std::uintptr_t>(
              info.lpMinimumApplicationAddress),
          .max_address = detail::address_cast<std::uintptr_t>(
              info.lpMaximumApplicationAddress)};
}

auto vm_alloc(std::uintptr_t address, std::size_t size, VMAccess access)
    -> std::expected<std::uintptr_t, Error>
{
  auto* result = VirtualAlloc(detail::address_cast<LPVOID>(address), size,
                              MEM_COMMIT | MEM_RESERVE, access);

  if (result == nullptr) { return std::unexpected{Error::Allocate}; }

  return detail::address_cast<std::uintptr_t>(result);
}

auto vm_free(std::uintptr_t address) -> void
{
  VirtualFree(detail::address_cast<LPVOID>(address), 0, MEM_RELEASE);
}

auto vm_protect(std::uintptr_t address, std::size_t size, VMAccess access,
                VMAccess& old_access) -> bool
{
  return static_cast<bool>(VirtualProtect(detail::address_cast<LPVOID>(address),
                                          size, access, &old_access));
}

auto vm_query(std::uintptr_t address) -> std::expected<VMInfo, Error>
{
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(detail::address_cast<LPVOID>(address), &mbi, sizeof(mbi)) ==
      0)
  {
    return std::unexpected{Error::Query};
  }

  VMInfo ret{
      .address = detail::address_cast<decltype(ret.address)>(mbi.BaseAddress),
      .size = mbi.RegionSize,
      .access = mbi.Protect,
      .free = mbi.State == MEM_FREE,
  };

  return ret;
}

}  // namespace VeilHook::Impl