#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <thread>

constexpr std::size_t kAllocationsPerSecond = 10000;
constexpr std::size_t kBatchesPerSecond = 100;
constexpr std::size_t kAllocationsPerBatch = kAllocationsPerSecond / kBatchesPerSecond;
constexpr auto kBatchInterval = std::chrono::milliseconds(1000 / kBatchesPerSecond);
constexpr std::size_t kLeakAllocationBytes = 1024;

// 通过 volatile 函数指针调用，避免优化器消除成对的 malloc/free。
using MallocFunction = void* (*)(std::size_t);
using FreeFunction = void (*)(void*);
MallocFunction volatile gMalloc = std::malloc;
FreeFunction volatile gFree = std::free;

[[gnu::noinline]]
bool AllocateBuffer(std::size_t bytes, bool leak)
{
    void* memory = gMalloc(bytes);
    if (memory == nullptr)
    {
        return false;
    }

    // 只触碰首尾字节，保留真实内存访问，减少填充操作对测量的影响。
    auto* data = static_cast<volatile unsigned char*>(memory);
    data[0] = 0xA5;
    data[bytes - 1] = 0x5A;
    if (!leak)
    {
        gFree(memory);
    }
    return true;
}

// 保留三条分配调用栈；在调用后更新计数，避免分支被优化成尾调用。
[[gnu::noinline]]
bool HandleSmallRequest(bool leak, std::size_t& allocations)
{
    if (!AllocateBuffer(leak ? kLeakAllocationBytes : 64, leak))
    {
        return false;
    }
    ++allocations;
    return true;
}

[[gnu::noinline]]
bool HandleMediumRequest(bool leak, std::size_t& allocations)
{
    if (!AllocateBuffer(leak ? kLeakAllocationBytes : 256, leak))
    {
        return false;
    }
    ++allocations;
    return true;
}

[[gnu::noinline]]
bool HandleLargeRequest(bool leak, std::size_t& allocations)
{
    if (!AllocateBuffer(leak ? kLeakAllocationBytes : 4096, leak))
    {
        return false;
    }
    ++allocations;
    return true;
}

bool RunAllocation(std::size_t iteration, bool leak, std::size_t& allocations)
{
    switch (iteration % 3)
    {
    case 0:
        return HandleSmallRequest(leak, allocations);
    case 1:
        return HandleMediumRequest(leak, allocations);
    default:
        return HandleLargeRequest(leak, allocations);
    }
}

int RunLeakLoop()
{
    using Clock = std::chrono::steady_clock;
    auto nextBatch = Clock::now();
    auto reportStart = nextBatch;
    auto nextLeak = nextBatch + std::chrono::seconds(1);
    std::size_t allocations = 0;
    std::size_t totalLeakedBytes = 0;
    std::size_t iteration = 0;
    while (true)
    {
        // 每次泄漏至少间隔一秒，持续产生泄漏，不限制运行期间的累计量。
        const bool leakThisBatch = Clock::now() >= nextLeak;
        for (std::size_t i = 0; i < kAllocationsPerBatch; ++i)
        {
            const bool leak = leakThisBatch && i == 0;
            if (!RunAllocation(iteration, leak, allocations))
            {
                std::fputs("Memory allocation failed.\n", stderr);
                return EXIT_FAILURE;
            }
            ++iteration;
            if (leak)
            {
                totalLeakedBytes += kLeakAllocationBytes;
                nextLeak = Clock::now() + std::chrono::seconds(1);
            }
        }

        const auto now = Clock::now();
        if (now - reportStart >= std::chrono::seconds(1))
        {
            const double seconds = std::chrono::duration<double>(now - reportStart).count();
            std::printf("malloc/s: %.0f, allocations: %zu, total leaked: %zu bytes\n",
                        allocations / seconds, allocations, totalLeakedBytes);
            std::fflush(stdout);
            allocations = 0;
            reportStart = now;
        }

        nextBatch += kBatchInterval;
        const auto finished = Clock::now();
        if (nextBatch < finished)
        {
            // 负载超过目标节拍时按实际能力运行，不堆积补发任务。
            nextBatch = finished;
        }
        std::this_thread::sleep_until(nextBatch);
    }
}

int main()
{
    std::printf("Target: %zu mallocs/s across 64/256/4096-byte branches; "
                "leak up to %zu bytes/s. Press Ctrl+C to stop.\n",
                kAllocationsPerSecond, kLeakAllocationBytes);
    std::fflush(stdout);
    return RunLeakLoop();
}
