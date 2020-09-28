# microhooks
X86 hooking library with functor callbacks support, so you can use lambdas with state, std::bind values etc...
Some examples:
```c++
microhooks::hook recvfrom_hook(&recvfrom, [](decltype(&recvfrom) orig, SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen) {
            int result = orig(s, buf, len, flags, from, fromlen);
            if (result >= 0)
                std::printf("recvfrom result: %d\nbuf: %p len: %d\n", result, buf, len);
            return result;
});
```
You can call original functions, pointer to it is provided by pointer as first argument in callback.
If result type of callback is void, then hook will call original function with arguments changed in callback(it passed by reference)
```c++
// Will be called with (123, b)
int add(int a, int b)
{
  return a + b;
}

void callback(int &a, int b)
{
  a = 123;
}

int main()
{
  microohooks::hook(&add, &callback);
  return 0;
}
```
Library didn't tested properly yet, it may not work or compile
