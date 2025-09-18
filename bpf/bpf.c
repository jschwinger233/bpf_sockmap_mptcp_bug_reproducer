// +build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <bpf_core_read.h>


struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct bpf_sock *);
	__type(value, u64);
	__uint(max_entries, 65535);
} tcp_sockets SEC(".maps");

SEC("sockops/tcp_lifetime")
int sockops_tcp_lifetime(struct bpf_sock_ops *skops)
{
	struct bpf_sock *sk = skops->sk;
	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_sock_hash_update(skops, &tcp_sockets, &sk, BPF_ANY);
		break;
	}

	return SK_PASS;
}


char _license[] SEC("license") = "GPL";
