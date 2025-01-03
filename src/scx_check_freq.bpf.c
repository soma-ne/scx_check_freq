#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct {
        __uint(type,BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct data_t {
        s32 cpu;
        bool is_idle;
};

s32 BPF_STRUCT_OPS(rr_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
        struct data_t *data;

	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

        data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
        if (!data)
                return cpu;

        data->cpu = cpu;
        data->is_idle = is_idle;

        bpf_ringbuf_submit(data, 0);

	return cpu;
}

s32 BPF_STRUCT_OPS(rr_init)
{
	return 0;
}

void BPF_STRUCT_OPS(rr_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(rr_ops,
		.select_cpu	= (void *)rr_select_cpu,
		.init		= (void *)rr_init,
		.exit		= (void *)rr_exit,
		.name		= "rr");
