#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_all.hpp>
#include <windows.h>
#include <cstdint>
#include "lazy_import.hpp"

TEST_CASE("Utility Functions - Hashing", "[utils]") {
    SECTION("FNV1a Hash Consistency") {
        auto hash1 = Fnv1aHash("GetProcAddress", 14);
        auto hash2 = Fnv1aHash("GetProcAddress", 14);
        auto hash3 = Fnv1aHash("Sleep", 5);

        REQUIRE(hash1 == hash2);
        REQUIRE(hash1 != hash3);
        // 验证宏定义的哈希是否一致
        REQUIRE(hash1 == FnHash(GetProcAddress));
    }

    SECTION("Case Sensitivity") {
        // 注意：当前 Fnv1aHash 是区分大小写的
        auto hash_upper = Fnv1aHash(L"KERNEL32.DLL", 12);
        auto hash_lower = Fnv1aHash(L"kernel32.dll", 12);

        // 如果你的 FindModule 逻辑依赖于 PEB 中的原始名称，
        // 需确保测试用例中的哈希与 PEB 字符串完全匹配（通常 PEB 里是混写的或全大写）
        CHECK(hash_upper != hash_lower);
    }
}

TEST_CASE("Module Resolution", "[module]") {
    SECTION("Find Known Modules") {
        // 获取系统真实句柄用于对比
        HMODULE real_k32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE real_nt = GetModuleHandleW(L"ntdll.dll");

        REQUIRE(real_k32 != nullptr);

        // 测试 FindModule
        auto found_k32 = FindModule(ModHash(kernel32.dll));
        auto found_nt = FindModule(ModHash(ntdll.dll));

        CHECK(found_k32 == real_k32);
        CHECK(found_nt == real_nt);
    }

    SECTION("Invalid Module") {
        auto invalid = FindModule(Fnv1aHash(L"non_existent.dll", 16));
        CHECK(invalid == nullptr);
    }
}

TEST_CASE("Export Resolution", "[export]") {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");

    SECTION("Find Known Exports") {
        FARPROC real_sleep = GetProcAddress(k32, "Sleep");
        REQUIRE(real_sleep != nullptr);

        auto found_sleep = FindExportFromModule(reinterpret_cast<std::uint8_t *>(k32), FnHash(Sleep));
        CHECK(reinterpret_cast<void *>(found_sleep) == reinterpret_cast<void *>(real_sleep));
    }

    SECTION("Invalid Export") {
        auto invalid = FindExportFromModule(reinterpret_cast<std::uint8_t *>(k32), 0xDEADBEEF);
        CHECK(invalid == nullptr);
    }
}

TEST_CASE("Lazy Import Interface & Caching", "[lazy]") {
    SECTION("Module Caching") {
        auto instance = LazyImportMod(kernel32.dll);

        // 第一次调用，触发 resolve
        void *ptr1 = instance.cached();
        REQUIRE(ptr1 != nullptr);

        // 检查内部静态变量是否已填充
        REQUIRE(instance.cached_value != nullptr);

        // 第二次调用，应返回缓存值
        void *ptr2 = instance.cached();
        CHECK(ptr1 == ptr2);
    }

    SECTION("Function Execution") {
        // 测试 Sleep 是否能被正确调用（通过执行耗时验证）
        auto start = GetTickCount64();

        // 使用宏定义的接口
        LazyFn(kernel32.dll, Sleep)(100);

        auto end = GetTickCount64();
        CHECK((end - start) >= 100);
    }

    SECTION("Return Value Check") {
        // 测试有返回值的函数
        auto current_id = LazyFn(kernel32.dll, GetCurrentProcessId)();
        CHECK(current_id == ::GetCurrentProcessId());
    }
}

TEST_CASE("Complex Dependency Thread Safety", "[concurrency]") {
    SECTION("Multi-threaded resolve") {
        // 虽然 Catch2 不是专门的压力测试工具，但我们可以简单验证
        // 多个线程同时调用同一个 LazyFn 是否会崩溃或产生多个值
        std::vector<std::uint32_t> results(10);

#pragma omp parallel for // 如果支持 OpenMP，或者手动开启多个 std::thread
        for (int i = 0; i < 10; ++i) {
            results[i] = LazyFn(kernel32.dll, GetTickCount)();
        }

        for (auto val : results) {
            CHECK(val > 0);
        }
    }
}

#include <thread>
#include <vector>

TEST_CASE("ImportFn cached is thread-stable", "[thread][cache]") {
    constexpr int N = 8;
    void *results[N]{};

    auto worker = [&](int i) { results[i] = reinterpret_cast<void *>(LazyFn(kernel32.dll, Sleep).cached()); };

    std::vector<std::thread> threads;
    for (int i = 0; i < N; ++i)
        threads.emplace_back(worker, i);

    for (auto &t : threads)
        t.join();

    for (int i = 1; i < N; ++i)
        REQUIRE(results[i] == results[0]);
}

TEST_CASE("Resolve user32!MessageBoxW", "[ImportFn][user32]") {
    printf("symbol %p", &MessageBoxW);
    auto lazy_msgbox = LazyFn(user32.dll, MessageBoxW);

    auto fn = lazy_msgbox.cached();
    REQUIRE(fn != nullptr);

    // 不真的弹窗，只比地址
    auto real = reinterpret_cast<decltype(fn)>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "MessageBoxW"));

    REQUIRE(fn == real);
}

TEST_CASE("LazyFn can call Sleep", "[ImportFn][call]") {
    auto lazy_sleep = LazyFn(kernel32.dll, Sleep);

    auto start = GetTickCount();
    lazy_sleep(50);
    auto end = GetTickCount();

    REQUIRE((end - start) >= 45); // 允许一点调度误差
}

TEST_CASE("ImportFn resolves Sleep correctly", "[ImportFn]") {
    auto lazy_sleep = LazyFn(kernel32.dll, Sleep);

    auto fn = lazy_sleep.cached();
    REQUIRE(fn != nullptr);

    // 和 GetProcAddress 对比
    auto real = reinterpret_cast<decltype(fn)>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Sleep"));

    REQUIRE(fn == real);
}
TEST_CASE("ImportModule cached() returns stable value", "[ImportModule][cache]") {
    auto importer = LazyImportMod(kernel32.dll);

    auto first = importer.cached();
    auto second = importer.cached();
    auto third = importer.cached();

    REQUIRE(first != nullptr);
    REQUIRE(first == second);
    REQUIRE(second == third);
}
TEST_CASE("ImportModule resolves kernel32.dll", "[ImportModule]") {
    auto mod = LazyImportMod(kernel32.dll).resolve();
    REQUIRE(mod != nullptr);

    // 和系统 API 结果对比
    REQUIRE(mod == GetModuleHandleW(L"kernel32.dll"));
}
