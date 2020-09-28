#ifndef X86_DETAIL_H
#define X86_DETAIL_H
#include <type_traits>
#include <functional>
#include "x86_traits.h"
#include "asmjit/asmjit.h"
#include <Windows.h>

namespace microhooks::arch
{
    namespace detail
    {
        std::size_t get_min_insn_len(std::size_t minimum_size, const std::uint8_t* ptr);
        std::vector<std::uint8_t> get_original_insns(std::uint8_t* exit_spring, std::uint8_t* source, std::size_t len);
        std::uint8_t *make_exit_spring(std::uint8_t* source, std::size_t orig_len);
        bool set_hook(std::uint8_t* source, std::uint8_t* thunk, std::size_t orig_len);
    }

    template <typename, typename>
    struct thunk_wrapper_detail {};
    // Incapsulates hooks architecture dependent code. Expects SourceType as second template argument
    template <typename HookType, typename Ret, typename... Args>
    struct thunk_wrapper_detail<HookType, Ret(__cdecl*)(Args...)>
    {
        using SourceType = Ret(__cdecl*)(Args...);
        static Ret __cdecl thunk_wrapper(HookType hook, std::uintptr_t retaddr, Args... args)
        {
            SourceType callable_source = reinterpret_cast<SourceType>(hook->_impl._exit_spring);
            using callback_return_type = decltype(hook->callback_wrapper(callable_source, std::function(hook->_callback), args...));
            if constexpr (std::is_void_v<callback_return_type>) {
                hook->callback_wrapper(callable_source, std::function(hook->_callback), args...);
                return callable_source(args...);
            } else {
                return hook->callback_wrapper(callable_source, std::function(hook->_callback), args...);
            }
        }
    };

    template <typename HookType, typename Ret, typename... Args>
    struct thunk_wrapper_detail<HookType, Ret(__fastcall*)(Args...)>
    {
        using SourceType = Ret(__fastcall*)(Args...);
        static Ret __fastcall thunk_wrapper(HookType hook, Args... args)
        {
            SourceType callable_source = reinterpret_cast<SourceType>(hook->_impl._exit_spring);
            using callback_return_type = decltype(hook->callback_wrapper(callable_source, std::function(hook->_callback), args...));
            if constexpr (std::is_void_v<callback_return_type>) {
                hook->callback_wrapper(callable_source, std::function(hook->_callback), args...);
                return callable_source(args...);
            } else {
                return hook->callback_wrapper(callable_source, std::function(hook->_callback), args...);
            }
        }
    };

    template <typename HookType, typename Ret, typename... Args>
    struct thunk_wrapper_detail<HookType, Ret(__stdcall*)(Args...)>
    {
        using SourceType = Ret(__stdcall*)(Args...);
        static Ret __stdcall thunk_wrapper(HookType hook, Args... args)
        {
            SourceType callable_source = reinterpret_cast<SourceType>(hook->_impl._exit_spring);
            using callback_return_type = decltype(hook->callback_wrapper(callable_source, std::function(hook->_callback), args...));
            if constexpr (std::is_void_v<callback_return_type>) {
                hook->callback_wrapper(callable_source, std::function(hook->_callback), args...);
                return callable_source(args...);
            } else {
                return hook->callback_wrapper(callable_source, std::function(hook->_callback), args...);
            }
        }
    };

    template <typename HookType, typename Ret, typename... Args>
    struct thunk_wrapper_detail<HookType, Ret(__thiscall*)(Args...)>
    {
        using SourceType = Ret(__thiscall*)(Args...);
        static Ret __stdcall thunk_wrapper(HookType hook, Args... args)
        {
            SourceType callable_source = reinterpret_cast<SourceType>(hook->_impl._exit_spring);
            if constexpr (std::is_member_function_pointer_v<typename std::remove_pointer_t<HookType>::callback_type>) {
                using callback_return_type = decltype(hook->callback_wrapper(callable_source, hook->_callback, args...));
                if constexpr (std::is_void_v<callback_return_type>) {
                    hook->callback_wrapper(callable_source, hook->_callback, args...);
                    return callable_source(args...);
                } else {
                    return hook->callback_wrapper(callable_source, hook->_callback, args...);
                }
            } else {
                using callback_return_type = decltype(hook->callback_wrapper(callable_source, std::function(hook->_callback), args...));
                if constexpr (std::is_void_v<callback_return_type>) {
                    hook->callback_wrapper(callable_source, std::function(hook->_callback), args...);
                    return callable_source(args...);
                } else {
                    return hook->callback_wrapper(callable_source, std::function(hook->_callback), args...);
                }
            }
        }
    };

    template <typename SourceType, typename HookType>
    struct hook_impl
    {
        std::uint8_t* _source;
        std::uint8_t* _exit_spring;
        std::uint8_t* _thunk;
        asmjit::JitRuntime* _rt;
        asmjit::CodeHolder _holder;
        std::unique_ptr<asmjit::x86::Assembler> _asmbl;
        HookType _hook;

        // Generates a thunk to jump from original function
        // Will not be deleted after hook_impl object destruction
        std::uint8_t* make_thunk()
        {
            using namespace asmjit::x86;
            constexpr auto source_conv = hook_traits::function_convention_v<SourceType>;
            constexpr bool is_method = source_conv == hook_traits::cconv::cthiscall;

            // Save original function return address
            if constexpr (source_conv != hook_traits::cconv::ccdecl) {
                _asmbl->pop(regs::eax);
            }
            // We should push ECX temporary, so we can provide a reference to it
            if constexpr (is_method) {
                _asmbl->push(regs::ecx);
            }

            if constexpr (source_conv != hook_traits::cconv::cfastcall) {
                _asmbl->push(_hook);
            } else {
                _asmbl->push(regs::ecx);
                _asmbl->mov(regs::ecx, _hook);
            }

            if constexpr (source_conv == hook_traits::cconv::ccdecl) {
                _asmbl->call(&thunk_wrapper_detail<HookType, SourceType>::thunk_wrapper);
                _asmbl->add(regs::esp, 4);
                _asmbl->ret();
            } else {
                _asmbl->push(regs::eax);
                _asmbl->jmp(&thunk_wrapper_detail<HookType, SourceType>::thunk_wrapper);
            }
            std::uint8_t* thunk;
            _rt->add(&thunk, &_holder);
            return thunk;
        }

        hook_impl(SourceType source, HookType hook) :
            _hook(hook), _source(reinterpret_cast<std::uint8_t*>(source)),
            _rt(new asmjit::JitRuntime), _thunk(nullptr)
        {
            _holder.init(_rt->environment());
            _asmbl.reset(new asmjit::x86::Assembler(&_holder));
            std::size_t orig_len = detail::get_min_insn_len(5, _source);
            _exit_spring = detail::make_exit_spring(_source, orig_len);
            if (!_exit_spring)
                return;
            _thunk = make_thunk();
            if (!_thunk)
                return;
            detail::set_hook(_source, _thunk, orig_len);
        }

        ~hook_impl()
        {
            if (!_thunk)
                return;
            *_thunk = 0xe9;
            *reinterpret_cast<std::uint32_t*>(_thunk + 1) = _exit_spring - _thunk - 5;
            // There is no memory leak, _thunk and _exit_spring should not be removed, there is jump to original function
            // after hook object destruction
        }
    };
};
#endif