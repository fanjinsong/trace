/* One PERF_EVENT sample contains both the native snapshot and Lua CallInfo chain. */
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>
#include <linux/errno.h>

#ifndef CONFIG_X86_64
#error "This profiler requires native x86-64 Linux"
#endif
#ifndef LUA_STATE_SLOT
#error "Supply Lua DWARF layout constants and the global state slot"
#endif
#if defined(PIDNS_DEV) != defined(PIDNS_INO)
#error "PIDNS_DEV and PIDNS_INO must be supplied together"
#endif
#ifndef RING_PAGES
#define RING_PAGES 2048
#endif

#define STACK_BYTES 16384
#define PAGE_BYTES 4096
#define MAX_LUA_FRAMES 64
#define SOURCE_BYTES 128
#define CIST_C 2

enum native_flags { READ_FAULT = 1, LIMIT = 2 };
enum lua_flags {
    LUA_NULL = 1,
    LUA_READ_FAULT = 2,
    LUA_INVALID = 4,
    LUA_DEPTH_LIMIT = 8,
    LUA_SOURCE_TRUNCATED = 16,
};
enum frame_kind { LUA_FRAME = 1, C_FRAME = 2 };
enum stat_index {
    TARGET_SAMPLES, KERNEL_SKIPPED, EMITTED, DROPPED, NATIVE_READ_FAULT, LUA_PARTIAL,
    STAT_COUNT,
};

struct lua_frame {
    u64 ci;
    u64 proto;
    u64 c_function;
    u32 callstatus;
    u32 kind;
    s32 linedefined;
    u32 reserved;
    char source[SOURCE_BYTES];
};

struct sample_event {
    u32 version;
    u32 size;
    u64 sequence;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 cpu;
    u32 stack_length;
    u32 native_flags;
    s32 native_error;
    u64 stack_base;
    u64 lua_state;
    u32 lua_count;
    u32 lua_flags;
    /* AMD64 DWARF register order, not pt_regs order. */
    u64 regs[17];
    struct lua_frame frames[MAX_LUA_FRAMES];
    u8 stack[STACK_BYTES];
};

_Static_assert(sizeof(struct lua_frame) == 168, "Lua frame ABI");
_Static_assert(__builtin_offsetof(struct sample_event, frames) == 208, "sample header ABI");
_Static_assert(__builtin_offsetof(struct sample_event, stack) == 10960, "native stack ABI");
_Static_assert(sizeof(struct sample_event) == 27344, "sample ABI");

BPF_RINGBUF_OUTPUT(events, RING_PAGES);
BPF_PERCPU_ARRAY(stats, u64, STAT_COUNT);
BPF_ARRAY(next_sequence, u64, 1);

static __always_inline void count(u32 index)
{
    u64 *value = stats.lookup(&index);
    if (value)
        (*value)++;
}

static __always_inline int target_ids(u32 *pid, u32 *tid)
{
#ifdef PIDNS_DEV
    struct bpf_pidns_info ids = {};
    if (bpf_get_ns_current_pid_tgid(PIDNS_DEV, PIDNS_INO, &ids, sizeof(ids)))
        return 0;
    *pid = ids.tgid;
    *tid = ids.pid;
#else
    u64 identity = bpf_get_current_pid_tgid();
    *pid = identity >> 32;
    *tid = (u32)identity;
#endif
    return *pid == TARGET_PID && *tid == *pid;
}

static __always_inline int user_pointer(u64 address)
{
    return address >= PAGE_BYTES && address < (1ULL << 47);
}

static __always_inline int read_pointer(u64 address, u64 *value)
{
    return bpf_probe_read_user(value, sizeof(*value), (void *)address);
}

static __always_inline void snapshot_native(struct bpf_perf_event_data *ctx,
                                           struct sample_event *event)
{
    event->stack_base = ctx->regs.sp;
    event->regs[0] = ctx->regs.ax;
    event->regs[1] = ctx->regs.dx;
    event->regs[2] = ctx->regs.cx;
    event->regs[3] = ctx->regs.bx;
    event->regs[4] = ctx->regs.si;
    event->regs[5] = ctx->regs.di;
    event->regs[6] = ctx->regs.bp;
    event->regs[7] = ctx->regs.sp;
    event->regs[8] = ctx->regs.r8;
    event->regs[9] = ctx->regs.r9;
    event->regs[10] = ctx->regs.r10;
    event->regs[11] = ctx->regs.r11;
    event->regs[12] = ctx->regs.r12;
    event->regs[13] = ctx->regs.r13;
    event->regs[14] = ctx->regs.r14;
    event->regs[15] = ctx->regs.r15;
    event->regs[16] = ctx->regs.ip;

    u64 base = event->stack_base;
    u64 amount = PAGE_BYTES - (base & (PAGE_BYTES - 1));
    asm volatile("" : "+r"(amount));
    if (!user_pointer(base) || !amount || amount > PAGE_BYTES) {
        event->native_flags = READ_FAULT;
        event->native_error = -EINVAL;
        return;
    }
    s32 error = bpf_probe_read_user(event->stack, amount, (void *)base);
    if (error) {
        event->native_flags = READ_FAULT;
        event->native_error = error;
        return;
    }
    u32 length = amount;
    u32 stopped = 0;
#pragma unroll
    for (int page = 0; page < STACK_BYTES / PAGE_BYTES; page++) {
        asm volatile("" : "+r"(length));
        if (stopped || length > STACK_BYTES - PAGE_BYTES)
            continue;
        error = bpf_probe_read_user(event->stack + length, PAGE_BYTES,
                                    (void *)(base + length));
        if (error) {
            event->native_flags |= READ_FAULT;
            stopped = 1;
            continue;
        }
        length += PAGE_BYTES;
    }
    /* Fixed-size pieces finish the last, possibly partial page. */
#pragma unroll
    for (int shift = 11; shift >= 0; shift--) {
        u32 block = 1U << shift;
        asm volatile("" : "+r"(length));
        if (stopped || length > STACK_BYTES - block)
            continue;
        error = bpf_probe_read_user(event->stack + length, block,
                                    (void *)(base + length));
        if (error) {
            event->native_flags |= READ_FAULT;
            stopped = 1;
            continue;
        }
        length += block;
    }
    event->stack_length = length;
    event->native_error = error;
    if (length == STACK_BYTES)
        event->native_flags |= LIMIT;
}

static __always_inline void snapshot_lua(struct sample_event *event)
{
    u64 state = 0, ci = 0, stack = 0, stack_last = 0;
    if (read_pointer(LUA_STATE_SLOT, &state)) {
        event->lua_flags = LUA_READ_FAULT;
        return;
    }
    event->lua_state = state;
    if (!state) {
        event->lua_flags = LUA_NULL;
        return;
    }
    if (!user_pointer(state) || (state & 7)) {
        event->lua_flags = LUA_INVALID;
        return;
    }
    if (read_pointer(state + OFF_LUA_STATE_CI, &ci) ||
        read_pointer(state + OFF_LUA_STATE_STACK, &stack) ||
        read_pointer(state + OFF_LUA_STATE_STACK_LAST, &stack_last)) {
        event->lua_flags = LUA_READ_FAULT;
        return;
    }
    if (!user_pointer(stack) || !user_pointer(stack_last) ||
        stack_last <= stack || stack_last - stack > (1ULL << 30)) {
        event->lua_flags = LUA_INVALID;
        return;
    }
    u64 base_ci = state + OFF_LUA_STATE_BASE_CI;
#pragma clang loop unroll(disable)
    for (int index = 0; index < MAX_LUA_FRAMES; index++) {
        if (ci == base_ci)
            return;
        if (!user_pointer(ci) || (ci & 7)) {
            event->lua_flags |= LUA_INVALID;
            return;
        }
        u64 func = 0, previous = 0;
        u16 status = 0;
        if (read_pointer(ci + OFF_CALLINFO_FUNC, &func) ||
            read_pointer(ci + OFF_CALLINFO_PREVIOUS, &previous) ||
            bpf_probe_read_user(&status, sizeof(status),
                                (void *)(ci + OFF_CALLINFO_CALLSTATUS))) {
            event->lua_flags |= LUA_READ_FAULT;
            return;
        }
        if (func < stack || func >= stack_last || stack_last - func < SIZE_STACKVALUE ||
            (func - stack) % SIZE_STACKVALUE || previous == ci) {
            event->lua_flags |= LUA_INVALID;
            return;
        }
        u64 value_address = func + OFF_STACKVALUE_VAL + OFF_TVALUE_VALUE;
        u8 tag = 0;
        if (bpf_probe_read_user(&tag, sizeof(tag),
                               (void *)(func + OFF_STACKVALUE_VAL + OFF_TVALUE_TT))) {
            event->lua_flags |= LUA_READ_FAULT;
            return;
        }
        struct lua_frame *frame = &event->frames[index];
        frame->ci = ci;
        frame->callstatus = status;
        if (status & CIST_C) {
            frame->kind = C_FRAME;
            u64 function = 0;
            if (tag == 22) { /* light C function */
                if (read_pointer(value_address + OFF_VALUE_F, &function)) {
                    event->lua_flags |= LUA_READ_FAULT;
                    return;
                }
            } else if (tag == (38 | 64)) { /* collectable C closure */
                u64 closure = 0;
                if (read_pointer(value_address + OFF_VALUE_GC, &closure) ||
                    !user_pointer(closure) ||
                    read_pointer(closure + OFF_CCLOSURE_F, &function)) {
                    event->lua_flags |= LUA_READ_FAULT;
                    return;
                }
            } else {
                event->lua_flags |= LUA_INVALID;
                return;
            }
            if (!user_pointer(function)) {
                event->lua_flags |= LUA_INVALID;
                return;
            }
            frame->c_function = function;
        } else {
            if (tag != (6 | 64)) { /* collectable Lua closure */
                event->lua_flags |= LUA_INVALID;
                return;
            }
            u64 closure = 0, proto = 0, source = 0;
            if (read_pointer(value_address + OFF_VALUE_GC, &closure) ||
                !user_pointer(closure) || read_pointer(closure + OFF_LCLOSURE_P, &proto) ||
                !user_pointer(proto) || read_pointer(proto + OFF_PROTO_SOURCE, &source) ||
                bpf_probe_read_user(&frame->linedefined, sizeof(frame->linedefined),
                                    (void *)(proto + OFF_PROTO_LINEDEFINED))) {
                event->lua_flags |= LUA_READ_FAULT;
                return;
            }
            if (!user_pointer(source) || frame->linedefined < 0) {
                event->lua_flags |= LUA_INVALID;
                return;
            }
            frame->kind = LUA_FRAME;
            frame->proto = proto;
            s32 amount = bpf_probe_read_user_str(frame->source, SOURCE_BYTES,
                                                 (void *)(source + OFF_TSTRING_CONTENTS));
            if (amount <= 0) {
                event->lua_flags |= LUA_READ_FAULT;
                return;
            }
            if (amount == SOURCE_BYTES)
                event->lua_flags |= LUA_SOURCE_TRUNCATED;
        }
        event->lua_count = index + 1;
        ci = previous;
    }
    if (ci != base_ci)
        event->lua_flags |= LUA_DEPTH_LIMIT;
}

int sample(struct bpf_perf_event_data *ctx)
{
    u32 pid = 0, tid = 0;
    if (!target_ids(&pid, &tid))
        return 0;
    count(TARGET_SAMPLES);
    /* PERF_EVENT register accesses must be 8 bytes; volatile prevents LLVM
     * from narrowing the CS load to 16 bits before applying this mask. */
    u64 cs = *(volatile u64 *)&ctx->regs.cs;
    if (!(cs & 3)) {
        count(KERNEL_SKIPPED);
        return 0;
    }
    struct sample_event *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) {
        count(DROPPED);
        return 0;
    }
    /* Clear unused frame/stack slots as well; no large BPF-local array. */
#pragma unroll
    for (int word = 0; word < sizeof(*event) / sizeof(u64); word++)
        ((volatile u64 *)event)[word] = 0;

    u32 zero = 0;
    u64 *sequence = next_sequence.lookup(&zero);
    if (!sequence) {
        events.ringbuf_discard(event, 0);
        count(DROPPED);
        return 0;
    }
    event->version = 1;
    event->size = sizeof(*event);
    event->sequence = __sync_fetch_and_add(sequence, 1) + 1;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->cpu = bpf_get_smp_processor_id();
    snapshot_native(ctx, event);
    snapshot_lua(event);
    if (event->native_flags & READ_FAULT)
        count(NATIVE_READ_FAULT);
    if (event->lua_flags & ~LUA_NULL)
        count(LUA_PARTIAL);
    events.ringbuf_submit(event, 0);
    count(EMITTED);
    return 0;
}
