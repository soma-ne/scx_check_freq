#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <scx/common.h>
#include <bpf/bpf.h>
#include "scx_rr.bpf.skel.h"

static volatile int exit_req;

static long long count = 0;

struct data_t {
	int cpu;
	int is_idle;
};

static void sigint_handler(int simple)
{
	exit_req = 1;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct data_t *e = data;
	count++;
	printf("cpu:%d, is_idle:%d, count:%lld\n", e->cpu, e->is_idle, count);
	return 0;
}

int main()
{
	int err;
	time_t before = 0;
	time_t after = 0;

	struct ring_buffer *rb = NULL;
	struct scx_rr *skel;
	struct bpf_link *link;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	skel = SCX_OPS_OPEN(rr_ops, scx_rr);
	SCX_OPS_LOAD(skel, rr_ops, scx_rr, uei);


	link = SCX_OPS_ATTACH(skel, rr_ops, scx_rr);
	
	before = time(NULL);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb)
		return -1;

	while (!exit_req & !UEI_EXITED(skel, uei)) {
		err = ring_buffer__poll(rb, 100);
		after = time(NULL);
		if (after - before >= 60)
			break;
		if (err < 0)
			break;
	}

	printf("time elapsed:%ld sec.\n", after - before);
	printf("total count: %lld, = %lld per sec.\n", count, count / (after - before));

	bpf_link__destroy(link);
	scx_rr__destroy(skel);
	return 0;
}
