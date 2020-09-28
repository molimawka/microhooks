#pragma once

namespace hook_traits
{
    enum class cconv
    {
        cthiscall, ccdecl, cstdcall, cfastcall
    };
    template <typename>
    struct function_convention {};
    template <typename Ret, typename... Args>
    struct function_convention<Ret(__stdcall*) (Args...)>
    {
        static constexpr cconv value = cconv::cstdcall;
    };
    template <typename Ret, typename... Args>
    struct function_convention<Ret(__cdecl*) (Args...)>
    {
        static constexpr cconv value = cconv::ccdecl;
    };
    template <typename Ret, typename Class, typename... Args>
    struct function_convention<Ret(Class::*)(Args...)>
    {
        static constexpr cconv value = cconv::cthiscall;
    };
    template <typename Ret, typename... Args>
    struct function_convention<Ret(__fastcall*) (Args...)>
    {
        static constexpr cconv value = cconv::cfastcall;
    };
    template <typename Ret, typename... Args>
    struct function_convention<Ret(__thiscall*) (Args...)>
    {
        static constexpr cconv value = cconv::cthiscall;
    };
    template <typename Func>
    constexpr cconv function_convention_v = function_convention<Func>::value;
};
