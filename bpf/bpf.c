// +build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>

#define MAX_ARG_LEN 128
#define TASK_COMM_LEN 16


struct event {
	u64 ts_ns;
	u64 sk;
	u32 pid;
	u32 local_ip4;
	u32 remote_ip4;
	u16 local_port;
	u16 remote_port;
	u8  op;  // skops->op for debugging
	u8 pname[TASK_COMM_LEN];
};

const struct event *_unused1 __attribute__((unused));


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

struct global {
	u64 cnt;
};

const static u32 ZERO_u32 = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct global);
	__uint(max_entries, 1);
} globals SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct bpf_sock *);
	__type(value, u32);
	__uint(max_entries, 1024);
} sockmap_sockets SEC(".maps");

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
	struct global *g = bpf_map_lookup_elem(&globals, &ZERO_u32);
	if (!g)
		return SK_PASS;
	if (g->cnt)
		return SK_PASS;
	struct bpf_sock *sk = skops->sk;
	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
		emit(skops);
		bpf_map_update_elem(&sockmap_sockets, &sk, &ZERO_u32, BPF_ANY);
		bpf_sock_hash_update(skops, &tcp_sockets, &sk, BPF_ANY);
		g->cnt++;
		break;
	}
	}

	return SK_PASS;
}

static __always_inline struct sock *get_sock_from_fd(u32 fd)
{
	struct task_struct *task = (struct task_struct *)(bpf_get_current_task());
	struct file **fds = BPF_CORE_READ(task, files, fdt, fd);
	struct file *file;
	bpf_probe_read_kernel(&file, sizeof(file), (void *)((u64)fds + (u64)fd * 8));
	if (!file)
		return NULL;
	struct socket *sock = (struct socket *)(BPF_CORE_READ(file, private_data));
	if (!sock)
		return NULL;
	return BPF_CORE_READ(sock, sk);
}
struct task_info {
	u32 pid;
	u8 comm[TASK_COMM_LEN];
};
const struct task_info *_unused_task_info __attribute__((unused));

struct get_real_comm_ctx {
	char *arg_buf;
	u8 l;
};

static int __noinline task_pname_cb(__u32 index, void *data)
{
	/* For string like: /usr/lib/sddm/sddm-helper --socket /tmp/sddm-auth1
	 * We extract "sddm-helper" from it.
	 */
	struct get_real_comm_ctx *ctx = (struct get_real_comm_ctx *)data;

	if (index >= MAX_ARG_LEN) // always false, just to make verifier happy
		return 1;
	if (unlikely(ctx->arg_buf[index] == '/'))
		ctx->l = index + 1;
	if (unlikely(ctx->arg_buf[index] == ' ' ||
		     ctx->arg_buf[index] == '\0')) {
		ctx->arg_buf[index] = '\0';
		return 1;
	}
	return 0;
}

static __always_inline void get_task_info(struct task_info *info)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	BPF_CORE_READ_INTO(&info->pid, task, tgid);

	char arg_buf[MAX_ARG_LEN];
	struct get_real_comm_ctx ctx = {};

	ctx.arg_buf = arg_buf;
	char *args = (void *)BPF_CORE_READ(task, mm, arg_start);
	bpf_core_read_user_str(arg_buf, MAX_ARG_LEN, args);

	if (bpf_loop(MAX_ARG_LEN, task_pname_cb, &ctx, 0) < 0)
		return;

	u8 offset = ctx.l;
	for (u8 i = 0; i < TASK_COMM_LEN; i++) {
		if (offset + i < MAX_ARG_LEN && arg_buf[offset + i] != '\0') {
			info->comm[i] = arg_buf[offset + i];
		} else {
			info->comm[i] = '\0';
			break;
		}
	}

	return;
}


static __always_inline int sys_accept(struct pt_regs *regs, s64 retval)
{
	if (retval < 0)
		return 0;

	u32 fd = (u32)retval;
	if (fd < 0)
		return 0;

	struct sock *sk = get_sock_from_fd(fd);
	if (!sk)
		return 0;


	if (!bpf_map_lookup_elem(&sockmap_sockets, &sk))
		return 0;

	struct task_info info = {};
	get_task_info(&info);

	struct event ev = {
		.ts_ns      = bpf_ktime_get_ns(),
		.sk	    = (u64)sk,
		.pid        = info.pid,
		.local_ip4  = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr),    // network byte order
		.remote_ip4 = BPF_CORE_READ(sk, __sk_common.skc_daddr),   // network byte order
		.local_port = BPF_CORE_READ(sk, __sk_common.skc_num), // host byte order
		.remote_port= bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)), // network byte order
		.op         = 0xFF, // sys_accept
	};
	__builtin_memcpy(&ev.pname, &info.comm, TASK_COMM_LEN);
	bpf_printk("sys_accept: pid=%d, comm=%s, fd=%d, sk=%p\n",
		   ev.pid, ev.pname, fd, sk);
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

	return 0;
}


SEC("fexit/__x64_sys_accept")
int BPF_PROG(fexit_sys_accept, struct pt_regs *regs, s64 retval)
{
	return sys_accept(regs, retval);
}

SEC("fexit/__x64_sys_accept4")
int BPF_PROG(fexit_sys_accept4, struct pt_regs *regs, s64 retval)
{
	return sys_accept(regs, retval);
}


char _license[] SEC("license") = "GPL";
