#ifndef VH_UTILITY_HPP
#define VH_UTILITY_HPP

#include <VeilHook/common.hpp>
#include <VeilHook/error.hpp>
#if defined(VH_PLATFORM_WINDOWS)
#define NOMINMAX
#include <Windows.h>
#include <winnt.h>
#endif

#include <expected>
#include <functional>
#include <mutex>
#include <unordered_set>


namespace VeilHook::Impl
{
    struct SystemInfo
    {
        std::uint32_t page_size;
        std::uint32_t granularity;
        std::uintptr_t min_address;
        std::uintptr_t max_address;
    };

    using VMAccess = DWORD;
    constexpr VMAccess VM_ACCESS_R { PAGE_READONLY };
    constexpr VMAccess VM_ACCESS_RW { PAGE_READWRITE };
    constexpr VMAccess VM_ACCESS_RX { PAGE_EXECUTE_READ };
    constexpr VMAccess VM_ACCESS_RWX { PAGE_EXECUTE_READWRITE };

    struct VMInfo
    {
        std::uintptr_t address;
        std::size_t size;
        VMAccess access;
        bool free;
    };


    [[nodiscard]] auto get_system_info() -> SystemInfo;
    [[nodiscard]] auto vm_alloc(std::uintptr_t, std::size_t, VMAccess) -> std::expected<std::uintptr_t, Error>;
    auto vm_free(std::uintptr_t) -> void;
    auto vm_protect(std::uintptr_t, std::size_t, VMAccess, VMAccess&) -> bool;
    [[nodiscard]] auto vm_query(std::uintptr_t) -> std::expected<VMInfo, Error>;

    class VMProtect
    {
        public:
        VMProtect(VMProtect&&) = delete;
        auto operator=(VMProtect&&) -> VMProtect& = delete;
        VMProtect(const VMProtect&) = delete;
        auto operator=(const VMProtect&) -> VMProtect& = delete;
        VMProtect(std::uintptr_t address, std::size_t length, VMAccess protect) : address_(address), length_(length)
        {
            status_ = vm_protect(address_, length_, protect, old_protect_); 
        }
        ~VMProtect() { 
            if (status_)
                { status_ = vm_protect(address_, length_, old_protect_, old_protect_); }
        }
        private:
        std::uintptr_t address_ = 0;
        std::size_t length_ = 0;
        bool status_ = false;
        VMAccess old_protect_ = 0;
    };
    struct VehEntry
    {
        using Callback = std::function<LONG(PEXCEPTION_POINTERS)>;
        std::uintptr_t start_address;
        std::uintptr_t end_address;
        Callback callback;
        auto operator==(const VehEntry& other) const
        {
            return start_address == other.start_address &&
                   end_address == other.end_address;
        }
        auto operator()(const VehEntry& other) const -> std::size_t
        {
            return std::hash<std::uintptr_t>{}(other.start_address) ^ (std::hash<std::uintptr_t>{}(other.end_address) << 1);
        }
    };

    class VehManager final
    {
        public:
        VehManager(const VehManager&) = delete;
        auto operator=(const VehManager&) -> VehManager& = delete;
        VehManager(VehManager&&) = delete;
        auto operator=(VehManager&&) -> VehManager& = delete;

        static auto instance() -> VehManager&;
        void Register(std::uintptr_t start_address, std::uintptr_t end_address, VehEntry::Callback callback);
        void Register(std::uintptr_t address, VehEntry::Callback  callback) { Register(address, address, std::move(callback)); }
        void Unregister(std::uintptr_t address);

        private:
        VehManager();
        ~VehManager();


        static auto VH_STDCALL _handler(PEXCEPTION_POINTERS) -> LONG;

        static std::mutex mutex_;
        static std::unordered_set<VehEntry> entries_;
        static void* handle_;
        
    };
}





#endif // VH_UTILITY_HPP