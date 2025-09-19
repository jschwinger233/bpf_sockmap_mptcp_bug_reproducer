// +build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <bpf_core_read.h>

struct event {
	u64 ts_ns;
	u64 sk;
	u32 pid;
	u32 local_ip4;
	u32 remote_ip4;
	u16 local_port;
	u16 remote_port;
	u8  op;  // skops->op for debugging
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024); // 256 KiB buffer
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct bpf_sock *);
	__type(value, __u64);
	__uint(max_entries, 1024);
} tcp_sockets SEC(".maps");

static __always_inline void emit(struct bpf_sock_ops *skops)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u32 pid = BPF_CORE_READ(task, tgid);

	struct event ev = {
		.ts_ns      = bpf_ktime_get_ns(),
		.sk	    = (u64)skops->sk,
		.pid        = pid,
		.local_ip4  = skops->local_ip4,    // network byte order
		.remote_ip4 = skops->remote_ip4,   // network byte order
		.local_port = bpf_ntohs(bpf_htonl(skops->local_port) >> 16),
		.remote_port= bpf_ntohs(skops->remote_port >> 16),
		.op         = skops->op,
	};

	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}

SEC("sockops/tcp_lifetime")
int sockops_tcp_lifetime(struct bpf_sock_ops *skops)
{
	struct bpf_sock *sk = skops->sk;
	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
		emit(skops);
		bpf_sock_hash_update(skops, &tcp_sockets, &sk, BPF_ANY);
		break;
	}
	}

	return SK_PASS;
}


char _license[] SEC("license") = "GPL";
