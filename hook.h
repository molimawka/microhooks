#ifndef HOOK_H
#define HOOK_H
#include <cstdint>
#include <functional>
#include "arch/x86_traits.h"
#include "arch/x86_detail.h"

namespace microhooks
{
    template<typename SourceType, typename CallbackType>
    class hook
    {
        template <typename Ret, typename... Args>
        static Ret callback_wrapper(SourceType source, std::function<Ret(Args...)> callback, std::add_lvalue_reference_t<Args>... args)
        {
            return callback(args...);
        }
        template <typename Ret, typename... Args>
        static Ret callback_wrapper(SourceType source, std::function<Ret(SourceType, Args...)> callback,
            std::add_lvalue_reference_t<Args>... args)
        {
            return callback(source, args...);
        }
        template <typename Ret, typename Class, typename... ArgsCallback>
        static Ret callback_wrapper(SourceType source, Ret(Class::* callback)(ArgsCallback...),
            std::add_lvalue_reference_t<Class*> object, std::add_lvalue_reference_t<ArgsCallback>... args)
        {
            return (object->*callback)(args...);
        }
        template <typename Ret, typename Class, typename... ArgsCallback>
        static Ret callback_wrapper(SourceType source, Ret(Class::* callback)(SourceType, ArgsCallback...),
            std::add_lvalue_reference_t<Class*> object, std::add_lvalue_reference_t<ArgsCallback>... args)
        {
            return (object->*callback)(source, args...);
        }
        using callback_type = CallbackType;
        using source_type = SourceType;

        CallbackType _callback;
        SourceType _source;
        arch::hook_impl<SourceType, hook<SourceType, CallbackType>*> _impl;
        friend struct arch::thunk_wrapper_detail<hook<SourceType, CallbackType>*, SourceType>;
    public:
        hook(SourceType source, CallbackType callback) :
            _callback(callback), _source(source), _impl(source, this)
        {
        }
    };
};

#endif // HOOK_H
