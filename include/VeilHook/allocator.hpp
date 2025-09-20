#ifndef VH_ALLOCATOR_HPP
#define VH_ALLOCATOR_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

#include "VeilHook/common.hpp"
#include "VeilHook/utility.hpp"

namespace VeilHook
{
class Allocator;
using MemoryRange = std::pair<std::uintptr_t, std::uintptr_t>;

class VH_API Allocation final : detail::NoCopy
{
 public:
  Allocation() = delete;
  Allocation(Allocation&& other) noexcept { *this = std::move(other); }
  auto operator=(Allocation&&) noexcept -> Allocation&;
  ~Allocation() { free(); };

  template <typename T>
  [[nodiscard]] auto data() const noexcept
  {
    return detail::address_cast<T>(address_);
  }
  [[nodiscard]] auto address() const noexcept { return address_; }
  [[nodiscard]] auto size() const noexcept { return size_; }
  void free() noexcept;
  explicit operator bool() const noexcept
  {
    return address_ != 0 && size_ != 0;
  }

 protected:
  friend class Allocator;
  Allocation(std::shared_ptr<Allocator> allocator, std::uintptr_t address,
             std::size_t size)
      : allocator_(std::move(allocator)), address_(address), size_(size)
  {
  }

 private:
  std::shared_ptr<Allocator> allocator_;
  std::uintptr_t address_{};
  std::size_t size_{};
};

class VH_API Allocator final : detail::NoCopy, detail::NoMove, public std::enable_shared_from_this<Allocator>
{
 public:
  Allocator() = default;
  ~Allocator() = default;

  static auto Get() -> std::shared_ptr<Allocator>;

  [[nodiscard]] auto Allocate(std::size_t size) -> std::optional<Allocation>
  {
    return Allocate({}, size, std::numeric_limits<std::size_t>::max());
  }

  [[nodiscard]] auto Allocate(
      const std::vector<std::uintptr_t>& desired_addresses, std::size_t size,
      std::size_t max_distance = 0x7FFF'FFFF) -> std::optional<Allocation>
  {
    if (size == 0) { return std::nullopt; }
    std::scoped_lock lock{mutex_};
    return _allocate(desired_addresses, size, max_distance);
  }

 private:
  friend class Allocation;
  struct MemoryBlock;
  struct Memory;
  [[nodiscard]] auto _in_range(
      std::uintptr_t address,
      const std::vector<std::uintptr_t>& desired_addresses,
      std::size_t max_distance) -> bool;
  [[nodiscard]] auto _make_memory(std::uintptr_t address, std::size_t size,
                                  Impl::VMAccess protect)
      -> std::unique_ptr<Memory>;
  [[nodiscard]] auto _allocate(
      const std::vector<std::uintptr_t>& desired_addresses, std::size_t size,
      std::size_t max_distance) -> std::optional<Allocation>;
  [[nodiscard]] auto _allocate_from_heap(
      const std::vector<std::uintptr_t>& desired_addresses, std::size_t size,
      std::size_t max_distance) -> std::optional<Allocation>;
   void _deallocate(std::uintptr_t address);
  [[nodiscard]] auto _allocate_memory(
      const std::vector<std::uintptr_t>& desired_addresses, std::size_t size,
      std::size_t max_distance) -> std::unique_ptr<Memory>;

  std::mutex mutex_;
  std::vector<std::unique_ptr<Memory>> memory_;
};

}  // namespace VeilHook

#endif  // VH_ALLOCATOR_HPP