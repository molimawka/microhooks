#include "x86_detail.h"
#include "hde32.h"
#include <iterator>

std::size_t microhooks::arch::detail::get_min_insn_len(std::size_t minimum_size, const std::uint8_t* ptr)
{
    hde32s hde;
    std::size_t total = 0;
    while (total < minimum_size)
        total += hde32_disasm(ptr + total, &hde);
    return total;
}

std::vector<std::uint8_t> microhooks::arch::detail::get_original_insns(std::uint8_t* exit_spring, std::uint8_t* source, std::size_t len)
{
    hde32s hde;
    std::size_t total = 0;
    std::vector<std::uint8_t> insns;
    while (total < len) {
        std::size_t size = hde32_disasm(source + total, &hde);
        // Seems like function already hooked, we should recalculate jump or call address
        // otherwise it will be broken after copying
        if (hde.opcode == 0xe9 || hde.opcode == 0xe8) {
            // off = dest - src - 5
            // dest = -(-off - src - 5) = off + src + 5
            std::uint32_t off = hde.imm.imm32;
            std::uint32_t dest = off + reinterpret_cast<std::uintptr_t>(source) + 5;
            std::uint32_t new_off = dest - reinterpret_cast<std::uintptr_t>(exit_spring) + total - 5;
            insns.push_back(hde.opcode);
            std::uint8_t* newoff_ptr = reinterpret_cast<std::uint8_t*>(&new_off);
            std::copy(newoff_ptr, newoff_ptr + 4, std::back_inserter(insns));
        } else {
            std::copy(source + total, source + total + size, std::back_inserter(insns));
        }
        total += size;
    }
    return insns;
}

std::uint8_t* microhooks::arch::detail::make_exit_spring(std::uint8_t* source, std::size_t orig_len)
{
    std::uint8_t *exit_spring =
        static_cast<std::uint8_t*>(
            VirtualAlloc(nullptr, orig_len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!exit_spring)
        return nullptr;
    auto insns = get_original_insns(exit_spring, source, orig_len);
    std::copy(insns.cbegin(), insns.cend(), exit_spring);
    exit_spring[orig_len] = 0xe9;
    *reinterpret_cast<std::uint32_t*>(exit_spring + orig_len + 1) =
        source - (exit_spring + orig_len);
    return exit_spring;
}

bool microhooks::arch::detail::set_hook(std::uint8_t *source, std::uint8_t* thunk, std::size_t orig_len)
{
    DWORD orig_prot;
    bool vpres = VirtualProtect(source, orig_len, PAGE_EXECUTE_READWRITE, &orig_prot);
    if (!vpres)
        return false;
    std::fill(source, source + 5, 0x90);
    *source = 0xe9;
    *reinterpret_cast<std::uint32_t*>(source + 1) = thunk - source - 5;
    VirtualProtect(source, orig_len, orig_prot, &orig_prot);
    return vpres;
}