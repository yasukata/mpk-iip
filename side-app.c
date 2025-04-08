/*
 *
 * Copyright 2025 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

static void *iip_ops_pkt_alloc(void *);
static void iip_ops_pkt_free(void *, void *);
static void *iip_ops_pkt_get_data(void *, void *);
static uint16_t iip_ops_pkt_get_len(void *, void *);
static void iip_ops_pkt_set_len(void *, uint16_t, void *);
static void iip_ops_pkt_increment_head(void *, uint16_t, void *);
static void iip_ops_pkt_decrement_tail(void *, uint16_t, void *);
static void *iip_ops_pkt_clone(void *, void *); /* assuming the entire packet chain is cloned while reference counts to the payload buffers are also incremented */
static void iip_ops_pkt_scatter_gather_chain_append(void *, void *, void *);
static void *iip_ops_pkt_scatter_gather_chain_get_next(void *, void *);
static uint16_t iip_ops_l2_hdr_len(void *, void *);
static uint8_t *iip_ops_l2_hdr_src_ptr(void *, void *);
static uint8_t *iip_ops_l2_hdr_dst_ptr(void *, void *);
static uint16_t iip_ops_l2_ethertype_be(void *, void *);
static uint16_t iip_ops_l2_addr_len(void *);
static void iip_ops_l2_broadcast_addr(uint8_t [], void *);
static void iip_ops_l2_hdr_craft(void *, uint8_t [], uint8_t [], uint16_t, void *);
static uint8_t iip_ops_l2_skip(void *, void *);
static void iip_ops_l2_flush(void *);
static void iip_ops_l2_push(void *, void *); /* assuming packet object is released by app */
static uint8_t iip_ops_arp_lhw(void *);
static uint8_t iip_ops_arp_lproto(void *);
static void iip_ops_arp_reply(void *, void *, void *);
static void iip_ops_icmp_reply(void *, void *, void *);
static uint8_t iip_ops_tcp_accept(void *, void *, void *);
static void *iip_ops_tcp_accepted(void *, void *, void *, void *);
static void *iip_ops_tcp_connected(void *, void *, void *, void *);
static void iip_ops_tcp_closed(void *, uint8_t [], uint32_t, uint16_t, uint8_t [], uint32_t, uint16_t, void *, void *);
static void iip_ops_tcp_payload(void *, void *, void *, void *, uint16_t, uint16_t, void *);
static void iip_ops_tcp_acked(void *, void *, void *, void *, void *);
static void iip_ops_udp_payload(void *, void *, void *);
static uint8_t iip_ops_nic_feature_offload_tx_scatter_gather(void *);
static uint8_t iip_ops_nic_feature_offload_ip4_rx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_ip4_tx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_tcp_rx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_tcp_tx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_tcp_tx_tso(void *);
static uint8_t iip_ops_nic_feature_offload_udp_rx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_udp_tx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_udp_tx_tso(void *);
static uint8_t iip_ops_nic_offload_ip4_rx_checksum(void *, void *);
static uint8_t iip_ops_nic_offload_udp_rx_checksum(void *, void *);
static uint8_t iip_ops_nic_offload_tcp_rx_checksum(void *, void *);
static void iip_ops_nic_offload_ip4_tx_checksum_mark(void *, void *);
static void iip_ops_nic_offload_tcp_tx_checksum_mark(void *, void *);
static void iip_ops_nic_offload_tcp_tx_tso_mark(void *, void *);
static void iip_ops_nic_offload_udp_tx_checksum_mark(void *, void *);
static void iip_ops_nic_offload_udp_tx_tso_mark(void *, void *);
static void iip_ops_util_now_ns(uint32_t [3], void *);

#include "side-both.c"

extern long MPK_IIP_run(long, ...);
extern long MPK_IIP_udp_send(long, ...);
extern long MPK_IIP_tcp_connect(long, ...);
extern long MPK_IIP_tcp_rxbuf_consumed(long, ...);
extern long MPK_IIP_tcp_close(long, ...);
extern long MPK_IIP_tcp_send(long, ...);
extern long MPK_IIP_arp_request(long, ...);
extern long MPK_IIP_add_tcp_conn(long, ...);
extern long MPK_IIP_add_pb(long, ...);
extern long MPK_IIP_BATCHED_tcp_send(long, ...);

extern uint32_t exposed_iip_workspace_size(void);
extern uint32_t exposed_iip_pb_size(void);
extern uint32_t exposed_iip_tcp_conn_size(void);

struct mpk_app_meta {
	struct {
		uint32_t cnt;
		struct {
			void *mem;
			void *handle;
			void *pkt;
			uint16_t tcp_flags;
			void *opaque;
		} args[NUM_MPKT];
	} app_tx_queue;
};

#define MPK_WORKSPACE_SIZE ((((((((((uintptr_t) MPKT(NULL, NUM_MPKT)) >> 12) + 1) << 12)) + _STACK_SIZE) >> 21) + 1) << 21)
#define _MPKAPPMETA(__mem) ((struct mpk_app_meta *)((uintptr_t) (__mem) + MPK_WORKSPACE_SIZE + 0x1000))

static char __opt_mask_signal = 0;

#define MPK_CALL_TOP \
	{ \
		sigset_t saved_mask; \
		if (__opt_mask_signal) { \
			assert(!sigprocmask(SIG_SETMASK, NULL, &saved_mask)); \
			{ \
				sigset_t mask; \
				sigfillset(&mask); \
				assert(!sigprocmask(SIG_SETMASK, &mask, NULL)); \
			} \
		}

#define MPK_CALL_BOTTOM \
		if (__opt_mask_signal) \
			assert(!sigprocmask(SIG_SETMASK, &saved_mask, NULL)); \
	}

#define mpk_memory_copy_64b(__pkru, __dst, __src, __len, __copy_out) \
	do { \
		MPK_CALL_TOP; \
		uint32_t ____l = 0; \
		while (____l < (uint32_t) (__len)) { \
			uint32_t ____ll = (uint32_t) (__len) - ____l; \
			if (____ll > 2048) { \
				____ll = 2048; \
			} \
			zmm_memcpy_64b(__pkru, ((void *)__dst) + ____l, ((void *)__src) + ____l, ____ll, __copy_out); \
			____l += ____ll; \
		} \
		MPK_CALL_BOTTOM; \
	} while (0)

void ____asm_impl(void)
{
	asm volatile (
	/* copy */
	".globl zmm_memcpy_64b \n\t"
	"zmm_memcpy_64b: \n\t"
	"cmpq $0, %rcx \n\t"
	"jne do_copy \n\t"
	"int3 \n\t"
	"do_copy: \n\t"
	"push %rbp \n\t"
	"movq %rsp, %rbp \n\t"
	"pushq %rbx \n\t"
	"pushq %rcx \n\t"
	"pushq %rdx \n\t"
	"pushq %r12 \n\t"
	"pushq %r13 \n\t"
	"movq %rdx, %r12 \n\t"
	"movq %rcx, %r13 \n\t"
	"xorl %ecx, %ecx \n\t"
#if __EXPERIMENT_NO_PKRU == 0
	"rdpkru \n\t"
#endif
	"movl %eax, %ebx \n\t"
	"cmpq $0, %r8 \n\t"
	"jne copy_out1 \n\t"
	"xorl %ecx, %ecx \n\t"
	"xorl %edx, %edx \n\t"
	"movl %edi, %eax \n\t"
#if __EXPERIMENT_NO_PKRU == 0
	"wrpkru \n\t"
#endif
	"copy_out1: \n\t"
	"vmovaps     (%r12),  %zmm0 \n\t"
	"cmpq $64, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps   64(%r12),  %zmm1 \n\t"
	"cmpq $128, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  128(%r12),  %zmm2 \n\t"
	"cmpq $128, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  192(%r12),  %zmm3 \n\t"
	"cmpq $192, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  256(%r12),  %zmm4 \n\t"
	"cmpq $256, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  320(%r12),  %zmm5 \n\t"
	"cmpq $320, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  384(%r12),  %zmm6 \n\t"
	"cmpq $384, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  448(%r12),  %zmm7 \n\t"
	"cmpq $448, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  512(%r12),  %zmm8 \n\t"
	"cmpq $512, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  576(%r12),  %zmm9 \n\t"
	"cmpq $576, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  640(%r12), %zmm10 \n\t"
	"cmpq $640, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  704(%r12), %zmm11 \n\t"
	"cmpq $704, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  768(%r12), %zmm12 \n\t"
	"cmpq $768, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  832(%r12), %zmm13 \n\t"
	"cmpq $832, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  896(%r12), %zmm14 \n\t"
	"cmpq $896, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps  960(%r12), %zmm15 \n\t"
	"cmpq $960, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1024(%r12), %zmm16 \n\t"
	"cmpq $1024, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1088(%r12), %zmm17 \n\t"
	"cmpq $1088, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1152(%r12), %zmm18 \n\t"
	"cmpq $1152, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1216(%r12), %zmm19 \n\t"
	"cmpq $1216, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1280(%r12), %zmm20 \n\t"
	"cmpq $1280, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1344(%r12), %zmm21 \n\t"
	"cmpq $1344, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1408(%r12), %zmm22 \n\t"
	"cmpq $1408, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1472(%r12), %zmm23 \n\t"
	"cmpq $1472, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1536(%r12), %zmm24 \n\t"
	"cmpq $1536, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1600(%r12), %zmm25 \n\t"
	"cmpq $1600, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1664(%r12), %zmm26 \n\t"
	"cmpq $1664, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1728(%r12), %zmm27 \n\t"
	"cmpq $1728, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1792(%r12), %zmm28 \n\t"
	"cmpq $1792, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1856(%r12), %zmm29 \n\t"
	"cmpq $1856, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1920(%r12), %zmm30 \n\t"
	"cmpq $1920, %r13 \n\t"
	"jle copy \n\t"
	"vmovaps 1984(%r12), %zmm31 \n\t"
	"copy: \n\t"
	"xorl %ecx, %ecx \n\t"
	"xorl %edx, %edx \n\t"
	"movl %edi, %eax \n\t"
	"cmpq $0, %r8 \n\t"
	"jne copy_out2 \n\t"
	"movl %ebx, %eax \n\t"
	"copy_out2: \n\t"
#if __EXPERIMENT_NO_PKRU == 0
	"wrpkru \n\t"
#endif
	"vmovaps  %zmm0,     (%rsi) \n\t"
	"cmpq $64, %r13 \n\t"
	"jle done \n\t"
	"vmovaps  %zmm1,   64(%rsi) \n\t"
	"cmpq $128, %r13 \n\t"
	"jle done \n\t"
	"vmovaps  %zmm2,  128(%rsi) \n\t"
	"cmpq $192, %r13 \n\t"
	"jle done \n\t"
	"vmovaps  %zmm3,  192(%rsi) \n\t"
	"cmpq $256, %r13 \n\t"
	"jle done \n\t"
	"vmovaps  %zmm4,  256(%rsi) \n\t"
	"cmpq $320, %r13 \n\t"
	"jle done \n\t"
	"vmovaps  %zmm5,  320(%rsi) \n\t"
	"cmpq $384, %r13 \n\t"
	"jle done \n\t"
	"vmovaps  %zmm6,  384(%rsi) \n\t"
	"cmpq $448, %r13 \n\t"
	"jle done \n\t"
	"vmovaps  %zmm7,  448(%rsi) \n\t"
	"cmpq $512, %r13 \n\t"
	"jle done \n\t"
	"vmovaps  %zmm8,  512(%rsi) \n\t"
	"cmpq $576, %r13 \n\t"
	"jle done \n\t"
	"vmovaps  %zmm9,  576(%rsi) \n\t"
	"cmpq $640, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm10,  640(%rsi) \n\t"
	"cmpq $704, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm11,  704(%rsi) \n\t"
	"cmpq $768, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm12,  768(%rsi) \n\t"
	"cmpq $832, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm13,  832(%rsi) \n\t"
	"cmpq $896, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm14,  896(%rsi) \n\t"
	"cmpq $960, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm15,  960(%rsi) \n\t"
	"cmpq $1024, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm16, 1024(%rsi) \n\t"
	"cmpq $1088, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm17, 1088(%rsi) \n\t"
	"cmpq $1152, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm18, 1152(%rsi) \n\t"
	"cmpq $1216, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm19, 1216(%rsi) \n\t"
	"cmpq $1280, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm20, 1280(%rsi) \n\t"
	"cmpq $1344, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm21, 1344(%rsi) \n\t"
	"cmpq $1408, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm22, 1408(%rsi) \n\t"
	"cmpq $1472, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm23, 1472(%rsi) \n\t"
	"cmpq $1536, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm24, 1536(%rsi) \n\t"
	"cmpq $1600, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm25, 1600(%rsi) \n\t"
	"cmpq $1664, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm26, 1664(%rsi) \n\t"
	"cmpq $1728, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm27, 1728(%rsi) \n\t"
	"cmpq $1792, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm28, 1792(%rsi) \n\t"
	"cmpq $1856, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm29, 1856(%rsi) \n\t"
	"cmpq $1920, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm30, 1920(%rsi) \n\t"
	"cmpq $1984, %r13 \n\t"
	"jle done \n\t"
	"vmovaps %zmm31, 1984(%rsi) \n\t"
	"done: \n\t"
	"cmpq $0, %r8 \n\t"
	"je copy_in1 \n\t"
	"xorl %ecx, %ecx \n\t"
	"xorl %edx, %edx \n\t"
	"movl %ebx, %eax \n\t"
#if __EXPERIMENT_NO_PKRU == 0
	"wrpkru \n\t"
#endif
	"copy_in1: \n\t"
	"movq %r13, %rax \n\t"
	"popq %r13 \n\t"
	"popq %r12 \n\t"
	"popq %rdx \n\t"
	"popq %rcx \n\t"
	"popq %rbx \n\t"
	"popq %rbp \n\t"
	"ret \n\t"

	/* call */
	".globl mpk_call \n\t"
	"mpk_call: \n\t"
	"pushq %rbx \n\t"
	"pushq %rcx \n\t"
	"pushq %rdx \n\t"
	"pushq %rbp \n\t"
	"movq %rsp, %rbp \n\t"
	"movq %rsi, %rsp \n\t"
	"xorl %ecx, %ecx \n\t"
#if __EXPERIMENT_NO_PKRU == 0
	"rdpkru \n\t"
#endif
	"movl %eax, %ebx \n\t"
	"xorl %ecx, %ecx \n\t"
	"xorl %edx, %edx \n\t"
	"movl %edi, %eax \n\t"
	"movl %ebx, %edi \n\t"
	"movq 16(%rbp), %rsi \n\t"
	"movq 8(%rbp), %rbx \n\t"
#if __EXPERIMENT_NO_PKRU == 0
	"wrpkru \n\t"
#endif
	"movq %rsi, %rcx \n\t"
	"movq %rbx, %rdx \n\t"
	"movq %rbp, %rsi \n\t"
	"andq $-16, %rsi \n\t"
	"movl %edi, %ebx \n\t"
	"andq $-16, %rsp \n\t"
	"call *%r9 \n\t"
	"movl %ebx, %edi \n\t"
	"movq %rax, %rbx \n\t"
	"xorl %ecx, %ecx \n\t"
	"xorl %edx, %edx \n\t"
	"movl %edi, %eax \n\t" /* XXX */
#if __EXPERIMENT_NO_PKRU == 0
	"wrpkru \n\t"
#endif
	"movq %rbx, %rax \n\t"
	"movq %rbp, %rsp \n\t"
	"popq %rbp \n\t"
	"popq %rdx \n\t"
	"popq %rcx \n\t"
	"popq %rbx \n\t"
	"ret \n\t"
	);
}

#if __EXPERIMENT_NO_PKRU
#define PKRU_ASSERT
#else
#define PKRU_ASSERT assert(orig_pkru == 0x55555549)
#endif

long MPK_IIP_OPS_pkt_alloc(long orig_pkru, long orig_stack __attribute__((unused)), long a0)
{
	PKRU_ASSERT; /* debug */
	return (uintptr_t) iip_ops_pkt_alloc((void *)((long *) a0) /* opaque */);
}

long MPK_IIP_OPS_pkt_free(long orig_pkru, long orig_stack __attribute__((unused)), long a0, long a1)
{
	PKRU_ASSERT; /* debug */
	iip_ops_pkt_free((void *) a0 /* pkt */, (void *)((long *) a1) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_pkt_get_data(long orig_pkru, long orig_stack __attribute__((unused)), long a0, long a1)
{
	PKRU_ASSERT; /* debug */
	return (uintptr_t) iip_ops_pkt_get_data((void *) a0 /* pkt */, (void *)((long *) a1) /* opaque */ );
}

long MPK_IIP_OPS_pkt_get_len(long orig_pkru, long orig_stack __attribute__((unused)), long a0, long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_pkt_get_len((void *) a0 /* pkt */, (void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_pkt_set_len(long orig_pkru, long orig_stack __attribute__((unused)), long a0, long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	iip_ops_pkt_set_len((void *) a0 /* pkt */, a1 /* len */, (void *)((long *) a2) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_pkt_increment_head(long orig_pkru, long orig_stack __attribute__((unused)), long a0, long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	iip_ops_pkt_increment_head((void *) a0 /* pkt */, a1 /* len */, (void *)((long *) a2) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_pkt_decrement_tail(long orig_pkru, long orig_stack __attribute__((unused)), long a0, long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	iip_ops_pkt_decrement_tail((void *) a0 /* pkt */, a1 /* len */, (void *)((long *) a2) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_pkt_clone(long orig_pkru, long orig_stack __attribute__((unused)), long a0, long a1)
{
	PKRU_ASSERT; /* debug */
	return (uintptr_t) iip_ops_pkt_clone((void *) a0 /* pkt */, (void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_pkt_scatter_gather_chain_append(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3)
{
	PKRU_ASSERT; /* debug */
	iip_ops_pkt_scatter_gather_chain_append((void *) a1 /* pkt_head */, (void *) a2 /* pkt_tail */, (void *)((long *) a3) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_pkt_scatter_gather_chain_get_next(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	return (uintptr_t) iip_ops_pkt_scatter_gather_chain_get_next((void *) a1 /* pkt_head */, (void *)((long *) a2) /* opaque */);
}

long MPK_IIP_OPS_util_now_ns(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	long t[8] __attribute__((aligned(64))) = { 0 };
	PKRU_ASSERT; /* debug */
	iip_ops_util_now_ns((uint32_t *) t /* t */, (void *)((long *) a2) /* opaque */);
	mpk_memory_copy_64b(orig_pkru, (uint8_t *) a1, (const uint8_t *) t, sizeof(t), 1);
	return 0;
}

long MPK_IIP_OPS_l2_hdr_len(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_l2_hdr_len((void *) a1 /* pkt */, (void *)((long *) a2) /* opaque */);
}

long MPK_IIP_OPS_l2_hdr_src_ptr(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	return (uintptr_t) iip_ops_l2_hdr_src_ptr((void *) a1 /* pkt */, (void *)((long *) a2) /* opaque */);
}

long MPK_IIP_OPS_l2_hdr_dst_ptr(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	return (uintptr_t) iip_ops_l2_hdr_dst_ptr((void *) a1 /* pkt */, (void *)((long *) a2) /* opaque */);
}

long MPK_IIP_OPS_l2_ethertype_be(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_l2_ethertype_be((void *) a1 /* pkt */, (void *)((long *) a2) /* opaque */);
}

long MPK_IIP_OPS_l2_addr_len(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_l2_addr_len((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_l2_broadcast_addr(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	long bcaddr[256] __attribute__((aligned(64)));
	PKRU_ASSERT; /* debug */
	{
		uint16_t l = iip_ops_l2_addr_len((void *)((long *) a2) /* opaque */);
		l = l % 64 ? (l / 64 + 1) * 64 : l;
		memset((void *) bcaddr, 0, l);
		iip_ops_l2_broadcast_addr((unsigned char *) bcaddr, (void *)((long *) a2) /* opaque */);
		mpk_memory_copy_64b(orig_pkru, (uint8_t *) a1, (const unsigned char *) bcaddr, l, 1);
	}
	return 0;
}

long MPK_IIP_OPS_l2_hdr_craft(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4, long a5)
{
	PKRU_ASSERT; /* debug */
	iip_ops_l2_hdr_craft((void *) a1 /* pkt */, (void *) a2 /* src */, (void *) a3 /* dst */, a4 /* ethertype_be */, (void *)((long *) a5) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_l2_skip(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_l2_skip((void *) a1 /* pkt */, (void *)((long *) a2) /* opaque */);
}

long MPK_IIP_OPS_l2_flush(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	iip_ops_l2_flush((void *)((long *) a1) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_l2_push(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	iip_ops_l2_push((void *) a1 /* _m */, (void *)((long *) a2) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_nic_feature_offload_tx_scatter_gather(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_feature_offload_tx_scatter_gather((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_nic_feature_offload_ip4_rx_checksum(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_feature_offload_ip4_rx_checksum((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_nic_feature_offload_ip4_tx_checksum(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_feature_offload_ip4_tx_checksum((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_nic_offload_ip4_rx_checksum(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_offload_ip4_rx_checksum((void *) a1 /* m */, (void *)((long *) a2) /* opaque */);
}

long MPK_IIP_OPS_nic_offload_tcp_rx_checksum(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_offload_tcp_rx_checksum((void *) a1 /* m */, (void *)((long *) a2) /* opaque */);
}

long MPK_IIP_OPS_nic_offload_udp_rx_checksum(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_offload_udp_rx_checksum((void *) a1 /* m */, (void *)((long *) a2) /* opaque */);
}

long MPK_IIP_OPS_nic_offload_ip4_tx_checksum_mark(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	iip_ops_nic_offload_ip4_tx_checksum_mark((void *) a1 /* m */, (void *)((long *) a2) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_nic_feature_offload_tcp_rx_checksum(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_feature_offload_tcp_rx_checksum((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_nic_feature_offload_tcp_tx_checksum(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_feature_offload_tcp_tx_checksum((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_nic_feature_offload_tcp_tx_tso(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_feature_offload_tcp_tx_tso((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_nic_offload_tcp_tx_checksum_mark(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	iip_ops_nic_offload_tcp_tx_checksum_mark((void *) a1 /* m */, (void *)((long *) a2) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_nic_offload_tcp_tx_tso_mark(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	iip_ops_nic_offload_tcp_tx_tso_mark((void *) a1 /* m */, (void *)((long *) a2) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_nic_feature_offload_udp_rx_checksum(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_feature_offload_udp_rx_checksum((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_nic_feature_offload_udp_tx_checksum(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_feature_offload_udp_tx_checksum((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_nic_feature_offload_udp_tx_tso(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_nic_feature_offload_udp_tx_tso((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_nic_offload_udp_tx_checksum_mark(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	iip_ops_nic_offload_udp_tx_checksum_mark((void *) a1 /* m */, (void *)((long *) a2) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_nic_offload_udp_tx_tso_mark(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	iip_ops_nic_offload_udp_tx_tso_mark((void *) a1 /* m */, (void *)((long *) a2) /* opaque */);
	return 0;
}

long MPK_IIP_OPS_arp_lhw(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_arp_lhw((void *)((long *) a1) /* opaque */);
}

long MPK_IIP_OPS_arp_lproto(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1)
{
	PKRU_ASSERT; /* debug */
	return iip_ops_arp_lproto((void *)((long *) a1) /* opaque */);
}

#define MPK_CB_TOP \
	{ \
	long *info = (long *)((void *) a1 + MPK_WORKSPACE_SIZE), saved_info[3]; \
	memcpy(saved_info, info, sizeof(saved_info)); \
	info[1] = orig_stack & 0xffffffffffffffc0; \
	info[2] = orig_pkru;

#define MPK_CB_BOTTOM \
	memcpy(info, saved_info, sizeof(saved_info)); \
	}

long MPK_IIP_OPS_arp_reply(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3)
{
	PKRU_ASSERT; /* debug */
	MPK_CB_TOP;
	iip_ops_arp_reply((void *)a1 /* _mem */, (void *) a2 /* m */, (void *)((long *) a3) /* opaque */);
	MPK_CB_BOTTOM;
	return 0;
}

long MPK_IIP_OPS_icmp_reply(long orig_pkru, long orig_stack, long a0, long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	MPK_CB_TOP;
	iip_ops_icmp_reply((void *) a0 /* _mem */, (void *) a1 /* m */, (void *)((long *) a2) /* opaque */);
	MPK_CB_BOTTOM;
	return 0;
}

long MPK_IIP_OPS_tcp_accept(long orig_pkru, long orig_stack, long a0, long a1, long a2)
{
	long ret;
	PKRU_ASSERT; /* debug */
	MPK_CB_TOP;
	ret = iip_ops_tcp_accept((void *)a0 /* mem */, (void *) a1 /* m */, (void *)((long *) a2) /* opaque */);
	MPK_CB_BOTTOM;
	return ret;
}

long MPK_IIP_OPS_tcp_accepted(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4)
{
	long ret;
	PKRU_ASSERT; /* debug */
	MPK_CB_TOP;
	ret = (uintptr_t) iip_ops_tcp_accepted((void *)a1 /* mem */, (void *) a2 /* handle */, (void *) a3 /* m */, (void *)((long *) a4) /* opaque */);
	MPK_CB_BOTTOM;
	return ret;
}

long MPK_IIP_OPS_tcp_connected(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4)
{
	long ret;
	PKRU_ASSERT; /* debug */
	MPK_CB_TOP;
	ret = (uintptr_t) iip_ops_tcp_connected((void *)a1 /* mem */, (void *) a2 /* handle */, (void *) a3 /* m */, (void *)((long *) a4) /* opaque */);
	MPK_CB_BOTTOM;
	return ret;
}

long MPK_IIP_OPS_tcp_payload(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	PKRU_ASSERT; /* debug */
	MPK_CB_TOP;
	iip_ops_tcp_payload((void *)a1 /* mem */, (void *) a2 /* handle */, (void *) a3 /* m */, (void *) a4 /* tcp_opaque */, a5 /* head_off */, a6 /* tail_off */, (void *)((long *) a7) /* opaque */);
	MPK_CB_BOTTOM;
	if (__EXPERIMENT_NO_BATCHING)
		iip_ops_pkt_free((void *) a3, (void *) a7);
	return 0;
}

long MPK_IIP_OPS_tcp_acked(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4, long a5)
{
	PKRU_ASSERT; /* debug */
	MPK_CB_TOP;
	iip_ops_tcp_acked((void *)a1 /* mem */, (void *) a2 /* handle */, (void *) a3 /* m */, (void *) a4 /* tcp_opaque */, (void *)((long *) a5) /* opaque */);
	MPK_CB_BOTTOM;
	if (__EXPERIMENT_NO_BATCHING)
		iip_ops_pkt_free((void *) a3, (void *) a5);
	return 0;
}

long MPK_IIP_OPS_tcp_closed(long orig_pkru, long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8, long a9)
{
	PKRU_ASSERT; /* debug */
	iip_ops_tcp_closed((void *) a1 /* handle */, (void *) a2 /* local_mac */, a3 /* local_ip4_be */, a4 /* local_port_be */, (void *) a5 /* peer_mac */, a6 /* peer_ip4_be */, a7 /* peer_port_be */, (void *) a8 /* tcp_opaque */, (void *)((long *) a9) /* opaque */);
	if (!__EXPERIMENT_NO_BATCHING) { /* cancel transmission */
		struct mpk_app_meta *am = _MPKAPPMETA((void *) a0);
		{
			uint32_t i;
			for (i = 0; i < am->app_tx_queue.cnt; i++) {
				if (am->app_tx_queue.args[i].handle == (void *) a1) {
					iip_ops_pkt_free(am->app_tx_queue.args[i].pkt, am->app_tx_queue.args[i].opaque);
					memmove(&am->app_tx_queue.args[i], &am->app_tx_queue.args[i + 1], sizeof(am->app_tx_queue.args[0]) * (am->app_tx_queue.cnt - 1 - i));
					am->app_tx_queue.cnt--;
					i--;
				}
			}
		}
	}
	return 0;
}

long MPK_IIP_OPS_udp_payload(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3)
{
	PKRU_ASSERT; /* debug */
	MPK_CB_TOP;
	iip_ops_udp_payload((void *)a1 /* mem */, (void *) a2 /* m */, (void *)((long *) a3) /* opaque */);
	MPK_CB_BOTTOM;
	return 0;
}

long MPK_IIP_OPS_BATCHED_l2_flush(long orig_pkru, long orig_stack __attribute__((unused)), long a0, long a1, long a2)
{
	long *arg = (long *) a0;
	PKRU_ASSERT; /* debug */
	{
		uint32_t i;
		for (i = 0; i < (uint32_t) a1; i++) {
			void *head = NULL;
			void *opaque = NULL;
			uint32_t tx_flags = 0;
			uint8_t stop = 0;
			while (!stop) {
				void *pkt;
				if (!arg[6]) {
					pkt = iip_ops_pkt_alloc((void *) arg[5]);
					assert(pkt);
					mpk_memory_copy_64b(orig_pkru, iip_ops_pkt_get_data(pkt, (void *) arg[5]), (void *) arg[1], arg[2], 0);
				} else {
					pkt = iip_ops_pkt_clone((void *) arg[6], (void *) arg[5]);
					assert(pkt);
					iip_ops_pkt_increment_head(pkt, arg[7], (void *) arg[5]);
				}
				iip_ops_pkt_set_len(pkt, arg[2], (void *) arg[5]);
				if (!head) {
					head = pkt;
					opaque = (void *) arg[5];
					tx_flags = (uint32_t) arg[3];
				} else
					iip_ops_pkt_scatter_gather_chain_append(head, pkt, opaque);
				if (!arg[4])
					stop = 1;
				arg = &arg[8];
			}
			if (tx_flags & (1U << 1))
				iip_ops_nic_offload_ip4_tx_checksum_mark(head, opaque);
			if (tx_flags & (1U << 2))
				iip_ops_nic_offload_tcp_tx_checksum_mark(head, opaque);
			if (tx_flags & (1U << 3))
				iip_ops_nic_offload_tcp_tx_tso_mark(head, opaque);
			if (tx_flags & (1U << 4))
				iip_ops_nic_offload_udp_tx_checksum_mark(head, opaque);
			if (tx_flags & (1U << 5))
				iip_ops_nic_offload_udp_tx_tso_mark(head, opaque);
			iip_ops_l2_push(head, opaque);
		}
	}
	iip_ops_l2_flush((void *) a2);
	return 0;
}

long MPK_IIP_OPS_BATCHED_tcp_input(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4, long a5)
{
	int j;
	PKRU_ASSERT; /* debug */
	for (j = 0; j < 2; j++) {
		long *arg;
		uint32_t cnt;
		if (j == 0) {
			arg = (long *) a2;
			cnt = (uint32_t) a3;
		} else {
			arg = (long *) a4;
			cnt = (uint32_t) a5;
		}
		{
			uint32_t i;
			for (i = 0; i < cnt; i++) {
				if (j == 0) {
					MPK_CB_TOP;
					iip_ops_tcp_payload((void *) arg[0], (void *) arg[3], (void *) arg[6], (void *) arg[4], arg[1], arg[2], (void *) arg[5]);
					MPK_CB_BOTTOM;
				} else {
					MPK_CB_TOP;
					iip_ops_tcp_acked((void *) arg[0], (void *) arg[3], (void *) arg[6], (void *) arg[4], (void *) arg[5]);
					MPK_CB_BOTTOM;
				}
				iip_ops_pkt_free((void *) arg[6], (void *) arg[5]);
				arg = &arg[8];
			}
		}
	}
	return 0;
}

static int __iip_mpk_pkey = 0, __iip_mpk_pkey_shared_ro = 0;

#define MPK_IIP_MAGIC (0x123456789abcdef) /* FIXME: received memory may accidentally have this value */
#define MPK_MAGIC (0xabcdef0) /* FIXME */

#include <sys/mman.h>

#define CHECK_INIT \
	long *info = (long *)((void *) _mem + MPK_WORKSPACE_SIZE); \
	if (info[0] != MPK_IIP_MAGIC) { \
		assert(exposed_iip_workspace_size() < __MPK_IIP_WORKSPACE_SIZE); \
		__iip_assert(MPK_WORKSPACE_SIZE <= 0xffffffff); \
		{ \
			struct mpkt_meta *mm = _MPKMETA(_mem); \
			if (mm->magic != MPK_MAGIC) { \
				{ \
					unsigned int i; \
					for (i = 0; i < NUM_MPKT_BUF; i++) \
						mm->mpktbuf_queue.p[i] = MPKTBUF(_mem, i); \
					mm->mpktbuf_queue.cnt = NUM_MPKT_BUF; \
				} \
				{ \
					unsigned int i; \
					for (i = 0; i < NUM_MPKT_BUF_LARGE; i++) \
						mm->mpktbuf_large_queue.p[i] = MPKTBUF_LARGE(_mem, i); \
					mm->mpktbuf_large_queue.cnt = NUM_MPKT_BUF_LARGE; \
				} \
				{ \
					unsigned int i; \
					for (i = 0; i < NUM_MPKT; i++) { \
						__iip_memset(MPKT(_mem, i), 0, sizeof(struct mpkt)); \
						mm->mpkt_queue.p[i] = MPKT(_mem, i); \
					} \
					mm->mpkt_queue.cnt = NUM_MPKT; \
				} \
				mm->magic = MPK_MAGIC; \
			} \
		} \
		{ \
			int err = pkey_mprotect(_mem, MPK_WORKSPACE_SIZE, PROT_READ | PROT_WRITE, __iip_mpk_pkey); \
			assert(!err); \
		} \
		printf("ISOLATED STACK: %lx -- %lx\n", ((uintptr_t) _mem + (uintptr_t) MPK_WORKSPACE_SIZE) - _STACK_SIZE, ((uintptr_t) _mem + (uintptr_t) MPK_WORKSPACE_SIZE)); \
		info[1] = ((uintptr_t) _mem + (uintptr_t) MPK_WORKSPACE_SIZE) - 64; \
		info[2] = 0; \
		{ \
			int i; \
			for (i = 0; i < 16; i++) { \
				if (i == __iip_mpk_pkey) \
					continue; \
				else if (i == __iip_mpk_pkey_shared_ro) \
					info[2] |= (1U << (2 * __iip_mpk_pkey_shared_ro + 1)); \
				else \
					info[2] |= (1U << (2 * i)); \
			} \
		} \
		printf("ISOLATED PKRU : 0x%lx\n", info[2]); \
		info[0] = MPK_IIP_MAGIC; \
	}

static uint32_t iip_workspace_size(void)
{
	/*
	 * layout:
	 * 0 ---------------------------------
	 *   workspace (__MPK_IIP_WORKSPACE_SIZE)
	 *   struct mpkt_meta (_MPKMETA)
	 *   misc (pb and tcp_conn) (_MPKMISC)
	 *   packet buffer 2KB (_MPKBUF_START)
	 *   packet buffer 64KB (MPKTBUF_LARGE)
	 *   packet info (MPKT)
	 *   stack
	 * MPK_WORKSPACE_SIZE ----------------
	 *   long *info
	 *     info[0]: MPK_IIP_MAGIC
	 *     info[1]: stack pointer to be applied at switch
	 *     info[2]: PKRU value to be applied at switch
	 * MPK_WORKSPACE_SIZE + (1U << 21) ---
	 */
	return MPK_WORKSPACE_SIZE + (1U << 21);
}

static uint32_t iip_pb_size(void)
{
	return 8; /* dummy value */
}

static uint32_t iip_tcp_conn_size(void)
{
	return 8; /* dummy value */
}

static void iip_add_pb(void *_mem, void *_p)
{
	CHECK_INIT;
	assert(info[9] + exposed_iip_pb_size() < _MISC_BUF_SIZE);
	_p = (void *) _MPKMISC(_mem) + info[9] /* misc cur */;
	{
		long rsp = info[1];
		{
			long arg[8] __attribute__((aligned(64))) = { 0 };
			arg[1] = (long) _mem;
			arg[2] = (long) _p;
			rsp -= sizeof(arg);
			mpk_memory_copy_64b(info[2], (void *) rsp, (void *) arg, sizeof(arg), 1);
		}
		MPK_CALL_TOP;
		mpk_call(info[2], rsp, 0, 0, 0, MPK_IIP_add_pb);
		MPK_CALL_BOTTOM;
	}
	info[9] += exposed_iip_pb_size();
}

static void iip_add_tcp_conn(void *_mem, void *_conn)
{
	CHECK_INIT;
	assert(info[9] + exposed_iip_tcp_conn_size() < _MISC_BUF_SIZE);
	_conn = (void *) _MPKMISC(_mem) + info[9] /* misc cur */;
	{
		long rsp = info[1];
		{
			long arg[8] __attribute__((aligned(64))) = { 0 };
			arg[1] = (long) _mem;
			arg[2] = (long) _conn;
			rsp -= sizeof(arg);
			mpk_memory_copy_64b(info[2], (void *) rsp, (void *) arg, sizeof(arg), 1);
		}
		MPK_CALL_TOP;
		mpk_call(info[2], rsp, 0, 0, 0, MPK_IIP_add_tcp_conn);
		MPK_CALL_BOTTOM;
	}
	info[9] += exposed_iip_tcp_conn_size();
}

static void iip_arp_request(void *_mem,
			    uint8_t local_mac[],
			    uint32_t local_ip4_be,
			    uint32_t target_ip4_be,
			    void *opaque)
{
	CHECK_INIT;
	{
		long rsp = info[1];
		{
			void *__local_mac;
			{
				uint16_t l = iip_ops_l2_addr_len(opaque), _l = l;
				l = l % 64 ? (l / 64 + 1) * 64 : l;
				rsp -= l;
				__local_mac = (void *) rsp;
				{
					uint8_t tmp[0xffff] __attribute__((aligned(64)));
					memcpy(tmp, local_mac, _l);
					mpk_memory_copy_64b(info[2], __local_mac, tmp, _l, 1);
				}
			}
			{
				long arg[8] __attribute__((aligned(64))) = { 0 };
				arg[1] = (long) _mem;
				arg[2] = (long) __local_mac;
				arg[3] = local_ip4_be;
				arg[4] = target_ip4_be;
				arg[5] = (long) opaque;
				rsp -= sizeof(arg);
				mpk_memory_copy_64b(info[2], (void *) rsp, (void *) arg, sizeof(arg), 1);
			}
		}
		MPK_CALL_TOP;
		mpk_call(info[2], rsp, 0, 0, 0, MPK_IIP_arp_request);
		MPK_CALL_BOTTOM;
	}
}

static uint16_t iip_tcp_close(void *_mem, void *_handle, void *opaque)
{
	CHECK_INIT;
	{
		long rsp = info[1];
		{
			long arg[8] __attribute__((aligned(64))) = { 0 };
			arg[1] = (long) _mem;
			arg[2] = (long) _handle;
			arg[3] = (long) opaque;
			rsp -= sizeof(arg);
			mpk_memory_copy_64b(info[2], (void *) rsp, (void *) arg, sizeof(arg), 1);
		}
		{
			long ret;
			MPK_CALL_TOP;
			ret = mpk_call(info[2], rsp, 0, 0, 0, MPK_IIP_tcp_close);
			MPK_CALL_BOTTOM;
			return ret;
		}
	}
}

static void iip_tcp_rxbuf_consumed(void *_mem, void *_handle, uint16_t cnt, void *opaque)
{
	CHECK_INIT;
	return;
	{
		long rsp = info[1];
		{
			long arg[8] __attribute__((aligned(64))) = { 0 };
			arg[1] = (long) _mem;
			arg[2] = (long) _handle;
			arg[3] = cnt;
			arg[4] = (long) opaque;
			rsp -= sizeof(arg);
			gpk_memory_copy_64b(info[2], (void *) rsp, (void *) arg, sizeof(arg), 1);
		}
		MPK_CALL_TOP;
		mpk_call(info[2], rsp, 0, 0, 0, MPK_IIP_tcp_rxbuf_consumed);
		MPK_CALL_BOTTOM;
	}
}

static uint16_t iip_tcp_send(void *_mem, void *_handle, void *pkt, uint16_t tcp_flags, void *opaque)
{
	CHECK_INIT;
	if (__EXPERIMENT_NO_BATCHING) {
		long rsp = info[1];
		{
			long arg[8] __attribute__((aligned(64))) = { 0 };
			arg[1] = (long) _mem;
			arg[2] = (long) _handle;
			arg[3] = (long) pkt;
			arg[4] = tcp_flags;
			arg[5] = (long) opaque;
			arg[6] = (long) iip_ops_pkt_get_data(pkt, opaque);
			arg[7] = iip_ops_pkt_get_len(pkt, opaque);
			rsp -= sizeof(arg);
			mpk_memory_copy_64b(info[2], (void *) rsp, (void *) arg, sizeof(arg), 1);
		}
		return mpk_call(info[2], rsp, info[3], info[4], info[5], MPK_IIP_tcp_send);
	} else {
		struct mpk_app_meta *am = _MPKAPPMETA(_mem);
		am->app_tx_queue.args[am->app_tx_queue.cnt].mem = _mem;
		am->app_tx_queue.args[am->app_tx_queue.cnt].handle = _handle;
		am->app_tx_queue.args[am->app_tx_queue.cnt].pkt = pkt;
		am->app_tx_queue.args[am->app_tx_queue.cnt].tcp_flags = tcp_flags;
		am->app_tx_queue.args[am->app_tx_queue.cnt].opaque = opaque;
		am->app_tx_queue.cnt++;
		return 0;
	}
}

static uint16_t iip_tcp_connect(void *_mem,
				uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
				uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
				void *opaque)
{
	CHECK_INIT;
	{
		long rsp = info[1];
		{
			void *__local_mac, *__peer_mac;
			{
				uint16_t l = iip_ops_l2_addr_len(opaque), _l = l;
				l = l % 64 ? (l / 64 + 1) * 64 : l;
				rsp -= l;
				__local_mac = (void *) rsp;
				{
					uint8_t tmp[0xffff] __attribute__((aligned(64)));
					memcpy(tmp, local_mac, _l);
					mpk_memory_copy_64b(info[2], __local_mac, tmp, _l, 1);
				}
				rsp -= l;
				__peer_mac = (void *) rsp;
				{
					uint8_t tmp[0xffff] __attribute__((aligned(64)));
					memcpy(tmp, peer_mac, _l);
					mpk_memory_copy_64b(info[2], __peer_mac, tmp, _l, 1);
				}
			}
			{
				long arg[16] __attribute__((aligned(64))) = { 0 };
				arg[1] = (long) _mem;
				arg[2] = (long) __local_mac;
				arg[3] = local_ip4_be;
				arg[4] = local_port_be;
				arg[5] = (long) __peer_mac;
				arg[6] = peer_ip4_be;
				arg[7] = peer_port_be;
				arg[8] = (long) opaque;
				rsp -= sizeof(arg);
				mpk_memory_copy_64b(info[2], (void *) rsp, (void *) arg, sizeof(arg), 1);
			}
		}
		{
			long ret;
			MPK_CALL_TOP;
			ret = mpk_call(info[2], rsp, 0, 0, 0, MPK_IIP_tcp_connect);
			MPK_CALL_BOTTOM;
			return ret;
		}
	}
}

static uint16_t iip_udp_send(void *_mem,
			     uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
			     uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
			     void *pkt, void *opaque)
{
	CHECK_INIT;
	{
		long rsp = info[1];
		{
			void *__local_mac, *__peer_mac;
			{
				uint16_t l = iip_ops_l2_addr_len(opaque), _l = l;
				l = l % 64 ? (l / 64 + 1) * 64 : l;
				rsp -= l;
				__local_mac = (void *) rsp;
				{
					uint8_t tmp[0xffff] __attribute__((aligned(64)));
					memcpy(tmp, local_mac, _l);
					mpk_memory_copy_64b(info[2], __local_mac, tmp, _l, 1);
				}
				rsp -= l;
				__peer_mac = (void *) rsp;
				{
					uint8_t tmp[0xffff] __attribute__((aligned(64)));
					memcpy(tmp, peer_mac, _l);
					mpk_memory_copy_64b(info[2], __peer_mac, tmp, _l, 1);
				}
			}
			{
				long arg[16] __attribute__((aligned(64))) = { 0 };
				arg[1] = (long) _mem;
				arg[2] = (long) __local_mac;
				arg[3] = local_ip4_be;
				arg[4] = local_port_be;
				arg[5] = (long) __peer_mac;
				arg[6] = peer_ip4_be;
				arg[7] = peer_port_be;
				arg[8] = (long) pkt;
				arg[9] = (long) opaque;
				rsp -= sizeof(arg);
				mpk_memory_copy_64b(info[2], (void *) rsp, (void *) arg, sizeof(arg), 1);
			}
		}
		{
			long ret;
			MPK_CALL_TOP;
			ret = mpk_call(info[2], rsp, 0, 0, 0, MPK_IIP_udp_send);
			MPK_CALL_BOTTOM;
			return ret;
		}
	}
}

static uint16_t iip_run(void *_mem, uint8_t mac[], uint32_t ip4_be, void *pkt[], uint16_t cnt, uint32_t *next_us, void *opaque)
{
	CHECK_INIT;
	if (!__EXPERIMENT_NO_BATCHING) { /* batched tcp send */
		struct mpk_app_meta *am = _MPKAPPMETA(_mem);
		if (am->app_tx_queue.cnt) {
			long rsp = (long)((unsigned long)(info[1] - am->app_tx_queue.cnt * 64) & 0xffffffffffffffc0);
			long _arg[256] __attribute__((aligned(64))) = { 0 }, *arg = _arg, copied = 0;
			{
				uint32_t i;
				for (i = 0; i < am->app_tx_queue.cnt; i++) {
					arg[0] = (long) am->app_tx_queue.args[i].mem;
					arg[1] = ((long) iip_ops_pkt_get_data(am->app_tx_queue.args[i].pkt, opaque));
					arg[2] = iip_ops_pkt_get_len(am->app_tx_queue.args[i].pkt, opaque);
					arg[3] = (long) am->app_tx_queue.args[i].handle;
					arg[4] = am->app_tx_queue.args[i].tcp_flags;
					arg[5] = (long) am->app_tx_queue.args[i].opaque;
					arg[6] = (long) am->app_tx_queue.args[i].pkt;
					arg = &arg[8];
					if (arg == &_arg[256]) {
						mpk_memory_copy_64b(info[2], (void *) rsp + copied, (void *) _arg, sizeof(_arg), 1);
						copied += sizeof(_arg);
						arg = _arg;
					}
				}
			}
			if (arg != _arg)
				mpk_memory_copy_64b(info[2], (void *) rsp + copied, (void *) _arg, (uintptr_t) arg - (uintptr_t) _arg, 1);
			MPK_CALL_TOP;
			mpk_call(info[2], rsp, (long) _mem, rsp, am->app_tx_queue.cnt, MPK_IIP_BATCHED_tcp_send);
			MPK_CALL_BOTTOM;
			am->app_tx_queue.cnt = 0;
		}
	}
	{
		long rsp = info[1] - (cnt + 2) * 64;
		{
			long _arg[256] __attribute__((aligned(64))) = { 0 }, *arg = _arg, copied = 0;
			{
				arg[0] = (long)({ struct timespec ts; assert(!clock_gettime(CLOCK_REALTIME, &ts)); ts.tv_sec * 1000000000UL + ts.tv_nsec; });
				arg[1] = (long) _mem;
				arg[2] = rsp + 64;
				arg[3] = ip4_be;
				arg[4] = rsp + 128;
				arg[5] = cnt;
				arg[6] = 0;
				arg[7] = (long) opaque;
				arg = &arg[8];
			}
			{
				assert(iip_ops_l2_addr_len(opaque) < 64);
				memcpy(arg, mac, iip_ops_l2_addr_len(opaque));
				arg = &arg[8];
			}
			if (cnt) {
				uint32_t i;
				for (i = 0; i < cnt; i++) {
					arg[1] = (long) iip_ops_pkt_get_data(pkt[i], opaque);
					arg[2] = iip_ops_pkt_get_len(pkt[i], opaque);
					arg[3] = (long) pkt[i];
					arg[4] = (iip_ops_l2_skip(pkt[i], opaque) ? (1U << 0) : 0)
						| (iip_ops_nic_feature_offload_ip4_rx_checksum(opaque)
								&& iip_ops_nic_offload_ip4_rx_checksum(pkt[i], opaque) ? (1U << 1) : 0)
						| (iip_ops_nic_feature_offload_tcp_rx_checksum(opaque)
								&& iip_ops_nic_offload_tcp_rx_checksum(pkt[i], opaque) ? (1U << 2) : 0)
						| (iip_ops_nic_feature_offload_udp_rx_checksum(opaque)
								&& iip_ops_nic_offload_udp_rx_checksum(pkt[i], opaque) ? (1U << 3) : 0);
					arg = &arg[8];
					if (arg == &_arg[256]) {
						mpk_memory_copy_64b(info[2], (void *) rsp + copied, (void *) _arg, sizeof(_arg), 1);
						copied += sizeof(_arg);
						arg = _arg;
					}
				}
			}
			if (arg != _arg)
				mpk_memory_copy_64b(info[2], (void *) rsp + copied, (void *) _arg, (uintptr_t) arg - (uintptr_t) _arg, 1);
		}
		MPK_CALL_TOP;
		*next_us = mpk_call(info[2], rsp, 0, 0, 0, MPK_IIP_run);
		MPK_CALL_BOTTOM;
	}
	return 0;
}

extern int (*printf_ptr)(const char *, ...);

extern char __debug_experiment_no_pkru(void);
extern char __debug_experiment_no_batching(void);
extern char __debug_experiment_no_memcopyskip(void);

__attribute__((constructor(0xffff))) void mpk_side_app_init(void)
{
	printf_ptr = (void *) IIP_OPS_DEBUG_PRINTF;
	__iip_mpk_pkey_shared_ro = pkey_alloc(0, 0);
	assert(__iip_mpk_pkey_shared_ro != -1);
#if __EXPERIMENT_NO_PKRU
	__iip_mpk_pkey = pkey_alloc(0, 0);
#else
	__iip_mpk_pkey = pkey_alloc(0, PKEY_DISABLE_ACCESS);
#endif
	assert(__iip_mpk_pkey != -1);
	{
		FILE *fp;
		assert((fp = fopen("/proc/self/maps", "r")) != NULL);
		{
			char buf[4096];
			while (fgets(buf, sizeof(buf), fp) != NULL) {
				if (!strstr(buf, "libisolate-iip-mpk.so"))
					continue;
				else
					printf("\x1b[33massign pkey%d\x1b[39m: %s", __iip_mpk_pkey_shared_ro, buf);
				{
					int i = 0;
					char addr[65] = { 0 };
					char *c = strtok(buf, " ");
					while (c != NULL) {
						switch (i) {
						case 0:
							strncpy(addr, c, sizeof(addr) - 1);
							break;
						case 1:
							{
								int mem_prot = 0;
								{
									size_t j;
									for (j = 0; j < strlen(c); j++) {
										if (c[j] == 'r')
											mem_prot |= PROT_READ;
										if (c[j] == 'w')
											mem_prot |= PROT_WRITE;
										if (c[j] == 'x')
											mem_prot |= PROT_EXEC;
									}
								}
								if (!(mem_prot & PROT_EXEC)) {
									size_t k;
									for (k = 0; k < strlen(addr); k++) {
										if (addr[k] == '-') {
											addr[k] = '\0';
											break;
										}
									}
									{
										int64_t from, to;
										from = strtol(&addr[0], NULL, 16);
										to = strtol(&addr[k + 1], NULL, 16);
										{
											int err = pkey_mprotect((void *) from, to - from, mem_prot, __iip_mpk_pkey_shared_ro);
											assert(!err);
										}
									}
								}
							}
							break;
						}
						if (i == 1)
							break;
						c = strtok(NULL, " ");
						i++;
					}
				}
			}
		}
		fclose(fp);
	}
	if (getenv("MPK_IIP_OPT_MASK_SIGNAL")) {
		__opt_mask_signal = 1;
		printf("\x1b[32msignal masking option is activated. note that this option reduces the performance.\x1b[39m\n");
	}
	assert(__EXPERIMENT_NO_PKRU == __debug_experiment_no_pkru());
	if (__EXPERIMENT_NO_PKRU)
		printf("\x1b[32mAPP: omit rdpkru/wrpkru.\x1b[39m\n");
	assert(__EXPERIMENT_NO_BATCHING == __debug_experiment_no_batching());
	if (__EXPERIMENT_NO_BATCHING)
		printf("\x1b[32mAPP: batching technique is not activated.\x1b[39m\n");
	assert(__EXPERIMENT_NO_MEMCOPYSKIP == __debug_experiment_no_memcopyskip());
	if (__EXPERIMENT_NO_MEMCOPYSKIP)
		printf("\x1b[32mAPP: memory copy skip technique is not activated.\x1b[39m\n");
}

/* XXX: re-definition for app */

struct iip_ip4_hdr {
	uint8_t vl;
	uint8_t tos;
	uint16_t len_be;
	uint16_t id_be;
	uint16_t off_be;
	uint8_t ttl;
	uint8_t proto;
	uint16_t csum_be;
	uint32_t src_be;
	uint32_t dst_be;
};

struct iip_arp_hdr {
	uint16_t hw_be;
	uint16_t proto_be;
	uint8_t lhw;
	uint8_t lproto;
	uint16_t op_be;
};

struct iip_icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t csum_be;
	struct {
		uint16_t id_be;
		uint16_t seq_be;
	} echo;
};

struct iip_l4_ip4_pseudo_hdr {
	uint32_t ip4_src_be;
	uint32_t ip4_dst_be;
	uint8_t pad;
	uint8_t proto;
	uint16_t len_be;
};

struct iip_tcp_hdr {
	uint16_t src_be;
	uint16_t dst_be;
	uint32_t seq_be;
	uint32_t ack_seq_be;
	uint16_t flags;
	uint16_t win_be;
	uint16_t csum_be;
	uint16_t urg_p_be;
};

struct iip_udp_hdr {
	uint16_t src_be;
	uint16_t dst_be;
	uint16_t len_be;
	uint16_t csum_be;
};

#define PB_IP4(__b) ((struct iip_ip4_hdr *)((uintptr_t) (iip_ops_pkt_get_data((__b), opaque)) + iip_ops_l2_hdr_len((__b), opaque)))
#define PB_ARP(__b) ((struct iip_arp_hdr *)(PB_IP4(__b)))
#define PB_ARP_HW_SENDER(__b) ((uint8_t *)((uintptr_t) PB_ARP(__b) + sizeof(struct iip_arp_hdr)))
#define PB_ARP_IP_SENDER(__b) ((uint8_t *)((uintptr_t) PB_ARP_HW_SENDER(__b) + PB_ARP(__b)->lhw))
#define PB_ARP_HW_TARGET(__b) ((uint8_t *)((uintptr_t) PB_ARP_IP_SENDER(__b) + PB_ARP(__b)->lproto))
#define PB_ARP_IP_TARGET(__b) ((uint8_t *)((uintptr_t) PB_ARP_HW_TARGET(__b) + PB_ARP(__b)->lhw))
#define PB_ICMP(__b) ((struct iip_icmp_hdr *)((uintptr_t) PB_IP4(__b) + (PB_IP4(__b)->vl & 0x0f) * 4))
#define PB_ICMP_PAYLOAD(__b) ((uint8_t *)((uintptr_t) PB_ICMP(__b) + sizeof(struct iip_icmp_hdr)))
#define PB_ICMP_PAYLOAD_LEN(__b) ((uint16_t)(htons(PB_IP4(__b)->len_be) - (PB_IP4(__b)->vl & 0x0f) * 4 - sizeof(struct iip_icmp_hdr)))
#define PB_TCP(__b) ((struct iip_tcp_hdr *)((uintptr_t) PB_IP4(__b) + (PB_IP4(__b)->vl & 0x0f) * 4))
#define PB_TCP_HDR_LEN(__b) ((uint16_t) ntohs(PB_TCP(__b)->flags) >> 12)
#define PB_TCP_HDR_HAS_FIN(__b) ((((uint8_t)(ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x01U) ? 1 : 0)
#define PB_TCP_HDR_HAS_SYN(__b) ((((uint8_t)(ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x02U) ? 1 : 0)
#define PB_TCP_HDR_HAS_RST(__b) ((((uint8_t)(ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x04U) ? 1 : 0)
#define PB_TCP_HDR_HAS_PSH(__b) ((((uint8_t)(ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x08U) ? 1 : 0)
#define PB_TCP_HDR_HAS_ACK(__b) ((((uint8_t)(ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x10U) ? 1 : 0)
#define PB_TCP_HDR_HAS_URG(__b) ((((uint8_t)(ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x20U) ? 1 : 0)
#define PB_TCP_HDR_HAS_ECE(__b) ((((uint8_t)(ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x40U) ? 1 : 0)
#define PB_TCP_HDR_HAS_CWR(__b) ((((uint8_t)(ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x80U) ? 1 : 0)
#define PB_TCP_HDR_SET_LEN(__b, __l) do { PB_TCP(__b)->flags = (htons(((__l) << 12) | ((uint8_t)(ntohs(PB_TCP(__b)->flags) & 0x3fU)))); } while (0)
#define PB_TCP_HDR_SET_FLAGS(__b, __f) do { PB_TCP(__b)->flags = (PB_TCP(__b)->flags & htons(~0x3fU)) | htons(__f); } while (0)
#define PB_TCP_PAYLOAD(__b) ((uint8_t *)((uintptr_t) PB_TCP(__b) + PB_TCP_HDR_LEN(__b) * 4))
#define PB_TCP_PAYLOAD_LEN(__b) ((uint16_t)(htons(PB_IP4(__b)->len_be) - (PB_IP4(__b)->vl & 0x0f) * 4 - PB_TCP_HDR_LEN(__b) * 4))
#define PB_TCP_OPT(__b) ((uint8_t *)((uintptr_t) PB_TCP(__b) + sizeof(struct iip_tcp_hdr)))
#define PB_TCP_OPTLEN(__b) (PB_TCP_HDR_LEN(__b) * 4 - sizeof(struct iip_tcp_hdr))
#define PB_UDP(__b) ((struct iip_udp_hdr *)((uintptr_t) PB_IP4(__b) + (PB_IP4(__b)->vl & 0x0f) * 4))
#define PB_UDP_PAYLOAD(__b) ((uint8_t *)((uintptr_t) PB_UDP(__b) + sizeof(struct iip_udp_hdr)))
#define PB_UDP_PAYLOAD_LEN(__b) ((uint16_t)(ntohs(PB_UDP(__b)->len_be)) - sizeof(struct iip_udp_hdr))

