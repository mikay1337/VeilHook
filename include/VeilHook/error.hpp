#ifndef VH_ERROR_HPP
#define VH_ERROR_HPP

#include <cstdint>
namespace VeilHook
{

enum class Error : std::uint8_t
{
  Success = 0,
  Allocate,
  Protect,
  Query,
  BadAllocation,
  FailedDecodeInstruction,
  UnsupportedInstruction,
  NotEnoughSpace,
  IpRelativeInstructionOutOfRange
};
}

#endif  // VH_ERROR_HPP