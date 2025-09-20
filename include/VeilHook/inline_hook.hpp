#ifndef VH_INLINE_HOOK_HPP
#define VH_INLINE_HOOK_HPP

#include <VeilHook/allocator.hpp>
#include <VeilHook/common.hpp>
#include <VeilHook/error.hpp>
#include <VeilHook/utility.hpp>
#include <array>
#include <expected>
#include <mutex>

namespace VeilHook
{
class VH_API InlineHook final : detail::NoCopy
{
 public:
  static auto Create(const std::shared_ptr<Allocator>& allocator,
                     std::uintptr_t target, std::uintptr_t destination)
      -> std::expected<InlineHook, Error>;
  static auto Create(std::uintptr_t target, std::uintptr_t destination)
      -> std::expected<InlineHook, Error>
  {
    return Create(Allocator::Get(), target, destination);
  }
  static auto Create(void* target, void* destination)
      -> std::expected<InlineHook, Error>
  {
    return Create(detail::address_cast<std::uintptr_t>(target),
                  detail::address_cast<std::uintptr_t>(destination));
  }

  InlineHook() noexcept = default;
  InlineHook(InlineHook&&) noexcept;
  auto operator=(InlineHook&&) noexcept -> InlineHook&;
  ~InlineHook();

  auto Enable() -> std::expected<void, Error>;
  auto Disable() -> std::expected<void, Error>;

  template<typename Ret, class... Args>
  Ret Call(Args&&... args)
  {
    return trampoline_->data<Ret(*)(Args...)>()(std::forward<Args>(args)...);
  }


 private:
  enum class Type : std::uint8_t
  {
    None,
    E9,
    FF
  };

  auto _setup(const std::shared_ptr<Allocator>& allocator,
              std::uintptr_t target, std::uintptr_t destination)
      -> std::expected<void, Error>;
  auto _e9_hook(const std::shared_ptr<Allocator>& allocator)
      -> std::expected<void, Error>;
  auto _ff_hook(const std::shared_ptr<Allocator>& allocator)
      -> std::expected<void, Error>;

  void _destroy() noexcept;

  std::uintptr_t target_{0};
  std::uintptr_t destination_{0};
  std::unique_ptr<Allocation> trampoline_{nullptr};
  std::array<std::uint8_t, 0x40> original_bytes_{};
  std::size_t original_bytes_size_{0};
  Type type_{Type::None};
  bool enabled_{false};
  std::recursive_mutex mutex_;
};
}  // namespace VeilHook

#endif