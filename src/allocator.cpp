#include "VeilHook/allocator.hpp"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>

#include "VeilHook/common.hpp"

namespace VeilHook
{

namespace
{
std::shared_ptr<Allocator> g_allocator = std::make_shared<Allocator>();
}

struct Allocator::MemoryBlock
{
  std::uintptr_t address{};
  std::size_t size{};
  bool free{};
  std::unique_ptr<MemoryBlock> next{nullptr};
};

struct Allocator::Memory
{
  enum : std::int8_t
  {
    Aligment = 0x10,
  };
  std::uintptr_t address{};
  std::size_t size{};
  std::unique_ptr<MemoryBlock> block{nullptr};
};

auto Allocator::Get() -> std::shared_ptr<Allocator> { return g_allocator; }

auto Allocation::operator=(Allocation&& other) noexcept -> Allocation&
{
  if (this != &other)
  {
    allocator_ = std::move(other.allocator_);
    address_ = other.address_;
    size_ = other.size_;
    other.address_ = 0;
    other.size_ = 0;
  }
  return *this;
}

void Allocation::free() noexcept 
{ 
  if (allocator_ and address_ != 0 and size_ != 0)
  {
    allocator_->_deallocate(address_);
    address_ = 0;
    size_ = 0;
    allocator_.reset();
  }
}

// clang-format off
auto Allocator::_in_range(std::uintptr_t address,
                          const std::vector<std::uintptr_t>& desired_addresses,
                          std::size_t max_distance) -> bool
{
  return std::ranges::all_of(desired_addresses, [&](std::uintptr_t desired_address)
    { const auto delta = (address > desired_address) ? 
      (address - desired_address) : (desired_address - address);  
       return delta <= max_distance; });
}
// clang-format on
auto Allocator::_make_memory(std::uintptr_t address, std::size_t size,
                             Impl::VMAccess protect) -> std::unique_ptr<Memory>
{
  if (auto result = Impl::vm_alloc(address, size, protect))
  {
    auto ret = std::make_unique<Memory>();
    ret->address = result.value();
    ret->size = size;
    ret->block = std::make_unique<MemoryBlock>();
    ret->block->address = ret->address;
    ret->block->size = size;
    ret->block->free = true;
    Impl::VMProtect protect(ret->address, ret->size, Impl::VM_ACCESS_RWX);
    std::fill_n(detail::address_cast<char*>(ret->address), ret->size, 0xCC);

    return ret;
  }
  return nullptr;
}

auto Allocator::_allocate_memory(
    const std::vector<std::uintptr_t>& desired_addresses, std::size_t size,
    std::size_t max_distance) -> std::unique_ptr<Memory>
{
  const auto si = Impl::get_system_info();
  const auto allocation_size = detail::align_up(size, si.granularity);

  if (desired_addresses.empty())
  {
    return _make_memory(0, allocation_size, Impl::VM_ACCESS_RWX);
  }

  auto desired_address = *desired_addresses.begin();
  auto search_start = si.min_address;
  auto search_end = si.max_address;

  if (desired_address - search_start > max_distance)
  {
    search_start = desired_address - max_distance;
  }
  if (search_end - desired_address > max_distance)
  {
    search_end = desired_address + max_distance;
  }

  search_start = std::max(search_start, si.min_address);
  search_end = std::min(search_end, si.max_address);
  desired_address = detail::align_up(desired_address, si.granularity);
  Impl::VMInfo mbi{};

  // Search backwards
  for (auto p = desired_address;
       p > search_start and _in_range(p, desired_addresses, max_distance);
       p = detail::align_down(mbi.address - 1, si.granularity))
  {
    auto query = Impl::vm_query(p);
    if (!query) { break; }
    mbi = query.value();
    if (not mbi.free) { continue; }

    if (_in_range(p, desired_addresses, max_distance))
    {
      if (auto result = _make_memory(p, allocation_size, Impl::VM_ACCESS_RWX))
      {
        return result;
      }
    }
  }

  // Search forwards
  for (auto p = desired_address;
       p < search_end and _in_range(p, desired_addresses, max_distance);
       p += mbi.size)
  {
    auto query = Impl::vm_query(p);
    if (!query) { break; }
    mbi = query.value();
    if (not mbi.free) { continue; }

    if (_in_range(p, desired_addresses, max_distance))
    {
      if (auto result = _make_memory(p, allocation_size, Impl::VM_ACCESS_RWX))
      {
        return result;
      }
    }
  }

  return nullptr;
}
auto Allocator::_allocate_from_heap(
    const std::vector<std::uintptr_t>& desired_addresses, std::size_t size,
       std::size_t max_distance) -> std::optional<Allocation>
{
  const std::size_t aligned_size = detail::align_up(size, Memory::Aligment);
  for (auto& heap : memory_)
  {
    if (heap->size < aligned_size) { continue; }

    for (auto* currentBlock = heap->block.get(); currentBlock != nullptr;
         currentBlock = currentBlock->next.get())
    {
      if ((not currentBlock->free) or currentBlock->size < aligned_size or
          (not _in_range(currentBlock->address, desired_addresses,
                         max_distance)))
      {
        continue;
      }

      if (currentBlock->size - aligned_size > 0)
      {
        auto new_free = std::make_unique<MemoryBlock>();
        new_free->address = currentBlock->address + aligned_size;
        new_free->size = currentBlock->size - aligned_size;
        new_free->free = true;
        new_free->next = std::move(currentBlock->next);
        currentBlock->next = std::move(new_free);
      }

      currentBlock->size = aligned_size;
      currentBlock->free = false;

      return Allocation(shared_from_this(), currentBlock->address, size);
    }
  }
  return std::nullopt;
};

auto Allocator::_allocate(const std::vector<std::uintptr_t>& desired_addresses,
                          std::size_t size, std::size_t max_distance)
    -> std::optional<Allocation>
{

  if (auto result = _allocate_from_heap(desired_addresses, size, max_distance); result) { return result; }

  if (auto heap =
          _allocate_memory(desired_addresses, size, max_distance);
      heap)
  {
    memory_.push_back(std::move(heap));
    return _allocate_from_heap(desired_addresses, size, max_distance);
  }
  return std::nullopt;
}

void Allocator::_deallocate(std::uintptr_t address)
{
  for (const auto& heap : memory_)
  {
    if (address < heap->address || address >= heap->address + heap->size)
    {
      continue;
    }
    MemoryBlock* currentBlock = heap->block.get();
    MemoryBlock* previousBlock = nullptr;
    for (; currentBlock != nullptr;
         previousBlock = currentBlock, currentBlock = currentBlock->next.get())
    {
      if (currentBlock->address == address)
      {
        currentBlock->free = true;
        // Try Merge free block
        while (currentBlock->next and currentBlock->next->free)
        {
          currentBlock->size += currentBlock->next->size;
          currentBlock->next = std::move(currentBlock->next->next);
        }

        // Try merge with previous block
        if (previousBlock != nullptr and previousBlock->free)
        {
          previousBlock->size += currentBlock->size;
          previousBlock->next = std::move(currentBlock->next);
        }
        return;
      }
    }
  }
}
}  // namespace VeilHook