/*
 * BCC malloc tracer for native Linux x86-64 processes.
 *
 * Allocation ownership lives in user space. Only in-flight malloc calls
 * are held in a map. Every successful malloc attempts a complete stack
 * capture in its own reserved record; free uses a separate, small-record ring.
 * Ordinary glibc malloc/free calls must return normally without hook reentry.
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/errno.h>

#ifndef CONFIG_X86_64
#error "This tracer requires an x86-64 kernel and a native x86-64 target"
#endif

#ifndef TARGET_PID
#define TARGET_PID 0
#endif
#if defined(PIDNS_DEV) != defined(PIDNS_INO)
#error "PIDNS_DEV and PIDNS_INO must be supplied together"
#endif
#ifndef STACK_MAX_BYTES
#define STACK_MAX_BYTES 16384
#endif
#ifndef MALLOC_PAGES
#define MALLOC_PAGES 16384
#endif
#ifndef FREE_PAGES
#define FREE_PAGES 1024
#endif

#if STACK_MAX_BYTES < 1 || STACK_MAX_BYTES > 32768
#error "STACK_MAX_BYTES must be between 1 and 32768"
#endif

#define STACK_CHUNK_BYTES 4096
/* Include struct malloc_event's final alignment padding when clearing it. */
#define STACK_STORAGE_BYTES ((STACK_MAX_BYTES + 7) & ~7)
#define ZERO_STACK_CHUNKS ((STACK_STORAGE_BYTES + STACK_CHUNK_BYTES - 1) / STACK_CHUNK_BYTES)

enum event_kind {
        MALLOC = 1,
        FREE = 2,
};

enum snapshot_flags {
        READ_FAULT = 1,
        LIMIT = 2,
};

struct event_header {
        u32 kind;
        u32 size;
        /* Global ordering across both rings; also the malloc allocation ID. */
        u64 sequence;
        u32 pid;
        u32 tid;
};

struct lifecycle_event {
        struct event_header header;
        u64 address;
        u64 size;
};

struct malloc_event {
        struct lifecycle_event allocation;
        u64 stack_base;
        /* DWARF x86-64 register numbers 0 through 16, not pt_regs order. */
        u64 regs[17];
        u32 max_bytes;
        u32 length;
        u32 flags;
        s32 read_error;
        u8 data[STACK_MAX_BYTES];
};

_Static_assert(sizeof(struct event_header) == 24, "event header ABI");
_Static_assert(sizeof(struct lifecycle_event) == 40, "lifecycle event ABI");
_Static_assert(__builtin_offsetof(struct malloc_event, data) == 200, "malloc snapshot ABI");
_Static_assert(sizeof(struct malloc_event) == 200 + STACK_STORAGE_BYTES, "malloc record padding ABI");

struct pending_call {
        u64 size;
};

BPF_RINGBUF_OUTPUT(malloc_events, MALLOC_PAGES);
BPF_RINGBUF_OUTPUT(free_events, FREE_PAGES);
BPF_ARRAY(next_event_id, u64, 1);
BPF_HASH(pending, u64, struct pending_call, 8192);

static __always_inline int namespace_ids(u64 pid_tgid, u32 *pid, u32 *tid)
{
#ifdef PIDNS_DEV
        struct bpf_pidns_info ids = {};
        if (bpf_get_ns_current_pid_tgid(PIDNS_DEV, PIDNS_INO, &ids, sizeof(ids)))
                return 0;
        *pid = ids.tgid;
        *tid = ids.pid;
#else
        *pid = pid_tgid >> 32;
        *tid = (u32)pid_tgid;
#endif
        return 1;
}

static __always_inline int fill_header(struct event_header *header, u32 kind,
                                      u32 size, u64 sequence, u64 pid_tgid)
{
        if (!namespace_ids(pid_tgid, &header->pid, &header->tid))
                return 0;
        header->kind = kind;
        header->size = size;
        header->sequence = sequence;
        return 1;
}

static __always_inline int is_target(u64 pid_tgid)
{
        u32 pid = 0, tid = 0;
        if (!namespace_ids(pid_tgid, &pid, &tid))
                return 0;
        return !TARGET_PID || pid == TARGET_PID;
}

static __always_inline u64 event_sequence(void)
{
        u32 zero = 0;
        u64 *sequence = next_event_id.lookup(&zero);
        if (!sequence)
                return 0;
        /* Allocate before transport: failed records leave detectable gaps.
         * Python merges both rings by this order, not by callback arrival.
         */
        return __sync_fetch_and_add(sequence, 1) + 1;
}

static __always_inline void emit_basic_malloc(u64 pid_tgid, u64 sequence,
                                             u64 address, u64 size)
{
        struct lifecycle_event event = {};
        if (!fill_header(&event.header, MALLOC, sizeof(event), sequence,
                         pid_tgid))
                return;
        event.address = address;
        event.size = size;
        malloc_events.ringbuf_output(&event, sizeof(event), 0);
}

static __always_inline void clear_stack_storage(struct malloc_event *event)
{
        /* Volatile fixed-size stores avoid a large, unsupported memset call.
         * Clear the unused stack tail and final struct padding as well.
         */
#pragma unroll
        for (int page = 0; page < ZERO_STACK_CHUNKS; page++) {
#pragma unroll
                for (int word = 0; word < STACK_CHUNK_BYTES / 8; word++) {
                        u32 offset = page * STACK_CHUNK_BYTES + word * 8;
                        if (offset < STACK_STORAGE_BYTES)
                                *(volatile u64 *)((u8 *)event +
                                        __builtin_offsetof(struct malloc_event, data) + offset) = 0;
                }
        }
}

static __always_inline void snapshot(struct pt_regs *ctx,
                                    struct malloc_event *event)
{
        event->stack_base = ctx->sp;
        event->regs[0] = ctx->ax;
        event->regs[1] = ctx->dx;
        event->regs[2] = ctx->cx;
        event->regs[3] = ctx->bx;
        event->regs[4] = ctx->si;
        event->regs[5] = ctx->di;
        event->regs[6] = ctx->bp;
        event->regs[7] = ctx->sp;
        event->regs[8] = ctx->r8;
        event->regs[9] = ctx->r9;
        event->regs[10] = ctx->r10;
        event->regs[11] = ctx->r11;
        event->regs[12] = ctx->r12;
        event->regs[13] = ctx->r13;
        event->regs[14] = ctx->r14;
        event->regs[15] = ctx->r15;
        event->regs[16] = ctx->ip;
        event->max_bytes = STACK_MAX_BYTES;
        event->length = 0;
        event->flags = 0;
        event->read_error = 0;
        clear_stack_storage(event);

        u64 base = ctx->sp;
        u32 length = 0;
        u32 stopped = 0;
        s32 read_error = 0;

        /* 首次读取到下一个页边界为止，同时不超过采集字节上限。
         * 目标地址固定为 data 起点，旧版验证器也能检查写入范围。
         */
        u64 amount = STACK_CHUNK_BYTES - (base & (STACK_CHUNK_BYTES - 1));
        if (amount > STACK_MAX_BYTES)
                amount = STACK_MAX_BYTES;
        asm volatile("" : "+r"(amount));
        if (!amount || amount > STACK_CHUNK_BYTES || amount > STACK_MAX_BYTES) {
                event->flags = READ_FAULT;
                event->read_error = -EINVAL;
                return;
        }
        read_error = bpf_probe_read_user(event->data, amount, (void *)base);
        if (read_error) {
                event->flags = READ_FAULT;
                event->read_error = read_error;
                return;
        }
        length = amount;

#if STACK_MAX_BYTES >= STACK_CHUNK_BYTES
#pragma unroll
        for (int page = 0; page < STACK_MAX_BYTES / STACK_CHUNK_BYTES; page++) {
                /* 用空汇编保留后面的显式边界检查。
                 * 否则 clang 可能根据 C 代码中的取值范围删掉检查；
                 * 加法被优化为按位或后，验证器又可能无法推导出原有范围。
                 */
                asm volatile("" : "+r"(length));
                if (stopped || length > STACK_MAX_BYTES - STACK_CHUNK_BYTES)
                        continue;
                read_error = bpf_probe_read_user(event->data + length,
                                                STACK_CHUNK_BYTES,
                                                (void *)(base + length));
                if (read_error) {
                        event->flags |= READ_FAULT;
                        stopped = 1;
                        continue;
                }
                length += STACK_CHUNK_BYTES;
        }
#endif

        /* 前面的循环每次只读完整的 4096 字节，最后可能还剩不足一页。
         * 将剩余字节拆成 2048、1024、...、1 字节的固定大小块。
         * 循环展开后，每次读取的大小都是常量；配合显式检查
         * length <= STACK_MAX_BYTES - block，验证器就能确认写入不会越界，
         * 无需推导两个变量之间的范围关系。这些读取都位于最后一页内。
         */
#pragma unroll
        for (int shift = 11; shift >= 0; shift--) {
                u32 block = 1U << shift;
                asm volatile("" : "+r"(length));
                if (stopped || block > STACK_MAX_BYTES || length > STACK_MAX_BYTES - block)
                        continue;
                read_error = bpf_probe_read_user(event->data + length, block,
                                                (void *)(base + length));
                if (read_error) {
                        event->flags |= READ_FAULT;
                        stopped = 1;
                        continue;
                }
                length += block;
        }

        event->length = length;
        event->read_error = read_error;
        if (length == STACK_MAX_BYTES)
                event->flags |= LIMIT;
        /* 某段内存不可读，并不能证明调用链已经结束。 */
}

int trace_malloc_enter(struct pt_regs *ctx)
{
        u64 pid_tgid = bpf_get_current_pid_tgid();
        if (!is_target(pid_tgid))
                return 0;
        struct pending_call call = {};
        call.size = ctx->di;
        pending.update(&pid_tgid, &call);
        return 0;
}

int trace_malloc_exit(struct pt_regs *ctx)
{
        u64 pid_tgid = bpf_get_current_pid_tgid();
        if (!is_target(pid_tgid))
                return 0;
        struct pending_call *saved = pending.lookup(&pid_tgid);
        if (!saved)
                return 0;
        struct pending_call call = *saved;
        pending.delete(&pid_tgid);
        if (!ctx->ax)
                return 0;

        u64 sequence = event_sequence();
        if (!sequence)
                return 0;
        struct malloc_event *event = malloc_events.ringbuf_reserve(sizeof(*event));
        if (!event) {
                /* Preserve the allocation even when its full snapshot cannot
                 * fit. This uses the same sequence and emits just one record.
                 */
                emit_basic_malloc(pid_tgid, sequence, ctx->ax, call.size);
                return 0;
        }
        if (!fill_header(&event->allocation.header, MALLOC, sizeof(*event),
                         sequence, pid_tgid)) {
                malloc_events.ringbuf_discard(event, 0);
                return 0;
        }
        event->allocation.address = ctx->ax;
        event->allocation.size = call.size;
        snapshot(ctx, event);
        malloc_events.ringbuf_submit(event, 0);
        return 0;
}

int trace_free_enter(struct pt_regs *ctx)
{
        u64 pid_tgid = bpf_get_current_pid_tgid();
        if (!is_target(pid_tgid) || !ctx->di)
                return 0;
        u64 sequence = event_sequence();
        if (!sequence)
                return 0;
        struct lifecycle_event event = {};
        if (!fill_header(&event.header, FREE, sizeof(event), sequence,
                         pid_tgid))
                return 0;
        event.address = ctx->di;
        free_events.ringbuf_output(&event, sizeof(event), 0);
        return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit)
{
        u64 pid_tgid = bpf_get_current_pid_tgid();
        pending.delete(&pid_tgid);
        return 0;
}
