#ifndef VH_COMMON_HPP
#define VH_COMMON_HPP

#include <algorithm>
#if defined(_WIN32) || defined(_WIN64)
#define VH_PLATFORM_WINDOWS
#elif defined(__APPLE__) || defined(__MACH__)
#define VH_PLATFORM_MACOS
#elif defined(__linux__)
#define VH_PLATFORM_LINUX
#elif defined(__unix__)
#define VH_PLATFORM_UNIX
#else
#define PLATFORM_UNKNOWN
#endif

#if defined(__clang__)
#define VH_COMPILER_CLANG
#elif defined(__GNUC__) || defined(__GNUG__)
#define VH_COMPILER_GCC
#elif defined(_MSC_VER)
#define VH_COMPILER_MSVC
#else
#error "Unsupported compiler"
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
#define VH_ARCH_X86_64
#elif defined(__i386__) || defined(_M_IX86)
#define VH_ARCH_X86_32
#elif defined(__aarch64__) || defined(_M_ARM64)
#error "Unsupported architecture
#elif defined(__arm__) || defined(_M_ARM)
#error "Unsupported architecture
#else
#error "Unknown architecture
#endif

#if defined(VH_PLATFORM_WINDOWS)
#if defined(VH_COMPILER_MSVC)
#define VH_CCALL __cdecl
#define VH_STDCALL __stdcall
#define VH_FASTCALL __fastcall
#define VH_THISCALL __thiscall
#define VH_VECTORCALL __vectorcall
#define VH_PACKED
#elif defined(VH_COMPILER_GCC) || defined(VH_COMPILER_CLANG)
#define VH_CCALL __attribute__((cdecl))
#define VH_STDCALL __attribute__((stdcall))
#define VH_FASTCALL __attribute__((fastcall))
#define VH_THISCALL __attribute__((thiscall))
#define VH_VECTORCALL
#define VH_PACKED __attribute__((__packed__))
#endif
#else
#define VH_CCALL
#define VH_STDCALL
#define VH_FASTCALL
#define VH_THISCALL
#define VH_VECTORCALL
#define VH_PACKED
#endif

#if defined(VH_COMPILER_MSVC)
#define VH_NOINLINE __declspec(noinline)
#elif defined(VH_COMPILER_GCC) || defined(VH_COMPILER_CLANG)
#define VH_NOINLINE __attribute__((noinline))
#endif

#if defined(VH_COMPILER_MSVC)
#define VH_DLLEXPORT __declspec(dllexport)
#define VH_DLLIMPORT __declspec(dllimport)
#elif defined(VH_COMPILER_GCC) || defined(VH_COMPILER_CLANG)
#define VH_DLLEXPORT __attribute__((visibility("default")))
#define VH_DLLIMPORT
#endif

#if defined(VEILHOOK_SHARED_LIB)
#define VH_API VH_DLLEXPORT
#elif defined(VH_SHARED_LIB)
#define VH_API VH_DLLIMPORT
#else
#define VH_API
#endif 

#include <cstdint>
#include <type_traits>

namespace VeilHook::detail
{

class NoCopy
{
 public:
  NoCopy() noexcept = default;
  ~NoCopy() noexcept = default;
  NoCopy(NoCopy&&) noexcept = default;
  auto operator=(NoCopy&&) noexcept -> NoCopy& = default;
  NoCopy(const NoCopy&) noexcept = delete;
  auto operator=(NoCopy&) noexcept -> NoCopy& = delete;
};

class NoMove
{
 public:
  NoMove() noexcept = default;
  ~NoMove() noexcept = default;
  NoMove(const NoMove&) noexcept = default;
  auto operator=(const NoMove&) noexcept -> NoMove& = default;
  NoMove(NoMove&&) noexcept = delete;
  auto operator=(NoMove&&) noexcept -> NoMove& = delete;
};

template <typename T = std::uintptr_t, typename U>
constexpr auto address_cast(U address) -> T
{
  if constexpr (std::is_same_v<T, U>) { return address; }
  else if constexpr (std::is_integral_v<T> && std::is_integral_v<U>)
  {
    return static_cast<T>(address);
  }
  else { return reinterpret_cast<T>(address); }
}

template <typename T>
constexpr auto align_up(T address, const std::size_t align) -> T
{
  return address_cast<T>((address_cast<std::uintptr_t>(address) + align - 1) &
                         ~(align - 1));
}

template <typename T>
constexpr auto align_down(T address, const std::size_t align) -> T
{
  return address_cast<T>(address_cast<std::uintptr_t>(address) & ~(align - 1));
}

constexpr auto copy(std::uintptr_t src, std::uintptr_t dst, std::size_t size)
{
  return std::copy_n(address_cast<char*>(src), size, address_cast<char*>(dst));
}

template <typename T>
constexpr auto fill(std::uintptr_t dst, std::size_t size, const T& value) {
  return std::fill_n(address_cast<T*>(dst), size, value);
}

template <typename T>
constexpr auto store(std::uintptr_t dst, const T& value) {
  return address_cast<T*>(dst)[0] = value;
}

}  // namespace detail

#endif // VH_COMMON_HPP