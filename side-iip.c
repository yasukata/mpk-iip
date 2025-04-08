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

typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef unsigned long  uintptr_t;

#define NULL (0)

int (*printf_ptr)(const char *, ...) = NULL;

static int ____debug_printf(const char *fmt, ...)
{
	uint32_t saved_pkru = __builtin_ia32_rdpkru();
	__builtin_ia32_wrpkru(0);
	if (printf_ptr) {
		void *a = __builtin_apply_args();
		__builtin_apply((void *) printf_ptr, a, 0x1000 /* to be large enough */);
	}
	__builtin_ia32_wrpkru(saved_pkru);
	return 0;
	(void) fmt;
}
#define IIP_OPS_DEBUG_PRINTF ____debug_printf

#define iip_ops_pkt_alloc				renamed_iip_ops_pkt_alloc
#define iip_ops_pkt_free				renamed_iip_ops_pkt_free
#define iip_ops_pkt_get_data				renamed_iip_ops_pkt_get_data
#define iip_ops_pkt_get_len				renamed_iip_ops_pkt_get_len
#define iip_ops_pkt_set_len				renamed_iip_ops_pkt_set_len
#define iip_ops_pkt_increment_head			renamed_iip_ops_pkt_increment_head
#define iip_ops_pkt_decrement_tail			renamed_iip_ops_pkt_decrement_tail
#define iip_ops_pkt_clone				renamed_iip_ops_pkt_clone
#define iip_ops_pkt_scatter_gather_chain_append		renamed_iip_ops_pkt_scatter_gather_chain_append
#define iip_ops_pkt_scatter_gather_chain_get_next	renamed_iip_ops_pkt_scatter_gather_chain_get_next
#define iip_ops_l2_hdr_len				renamed_iip_ops_l2_hdr_len
#define iip_ops_l2_hdr_src_ptr				renamed_iip_ops_l2_hdr_src_ptr
#define iip_ops_l2_hdr_dst_ptr				renamed_iip_ops_l2_hdr_dst_ptr
#define iip_ops_l2_ethertype_be				renamed_iip_ops_l2_ethertype_be
#define iip_ops_l2_addr_len				renamed_iip_ops_l2_addr_len
#define iip_ops_l2_broadcast_addr			renamed_iip_ops_l2_broadcast_addr
#define iip_ops_l2_hdr_craft				renamed_iip_ops_l2_hdr_craft
#define iip_ops_l2_skip					renamed_iip_ops_l2_skip
#define iip_ops_l2_flush				renamed_iip_ops_l2_flush
#define iip_ops_l2_push					renamed_iip_ops_l2_push
#define iip_ops_arp_lhw					renamed_iip_ops_arp_lhw
#define iip_ops_arp_lproto				renamed_iip_ops_arp_lproto
#define iip_ops_arp_reply				renamed_iip_ops_arp_reply
#define iip_ops_icmp_reply				renamed_iip_ops_icmp_reply
#define iip_ops_tcp_accept				renamed_iip_ops_tcp_accept
#define iip_ops_tcp_accepted				renamed_iip_ops_tcp_accepted
#define iip_ops_tcp_connected				renamed_iip_ops_tcp_connected
#define iip_ops_tcp_closed				renamed_iip_ops_tcp_closed
#define iip_ops_tcp_payload				renamed_iip_ops_tcp_payload
#define iip_ops_tcp_acked				renamed_iip_ops_tcp_acked
#define iip_ops_udp_payload				renamed_iip_ops_udp_payload
#define iip_ops_nic_feature_offload_tx_scatter_gather	renamed_iip_ops_nic_feature_offload_tx_scatter_gather
#define iip_ops_nic_feature_offload_ip4_rx_checksum	renamed_iip_ops_nic_feature_offload_ip4_rx_checksum
#define iip_ops_nic_feature_offload_ip4_tx_checksum	renamed_iip_ops_nic_feature_offload_ip4_tx_checksum
#define iip_ops_nic_feature_offload_tcp_rx_checksum	renamed_iip_ops_nic_feature_offload_tcp_rx_checksum
#define iip_ops_nic_feature_offload_tcp_tx_checksum	renamed_iip_ops_nic_feature_offload_tcp_tx_checksum
#define iip_ops_nic_feature_offload_tcp_tx_tso		renamed_iip_ops_nic_feature_offload_tcp_tx_tso
#define iip_ops_nic_feature_offload_udp_rx_checksum	renamed_iip_ops_nic_feature_offload_udp_rx_checksum
#define iip_ops_nic_feature_offload_udp_tx_checksum	renamed_iip_ops_nic_feature_offload_udp_tx_checksum
#define iip_ops_nic_feature_offload_udp_tx_tso		renamed_iip_ops_nic_feature_offload_udp_tx_tso
#define iip_ops_nic_offload_ip4_rx_checksum		renamed_iip_ops_nic_offload_ip4_rx_checksum
#define iip_ops_nic_offload_udp_rx_checksum		renamed_iip_ops_nic_offload_udp_rx_checksum
#define iip_ops_nic_offload_tcp_rx_checksum		renamed_iip_ops_nic_offload_tcp_rx_checksum
#define iip_ops_nic_offload_ip4_tx_checksum_mark	renamed_iip_ops_nic_offload_ip4_tx_checksum_mark
#define iip_ops_nic_offload_tcp_tx_checksum_mark	renamed_iip_ops_nic_offload_tcp_tx_checksum_mark
#define iip_ops_nic_offload_tcp_tx_tso_mark		renamed_iip_ops_nic_offload_tcp_tx_tso_mark
#define iip_ops_nic_offload_udp_tx_checksum_mark	renamed_iip_ops_nic_offload_udp_tx_checksum_mark
#define iip_ops_nic_offload_udp_tx_tso_mark		renamed_iip_ops_nic_offload_udp_tx_tso_mark
#define iip_ops_util_now_ns				renamed_iip_ops_util_now_ns

#define iip_run						renamed_iip_run
#define iip_udp_send					renamed_iip_udp_send
#define iip_tcp_connect					renamed_iip_tcp_connect
#define iip_tcp_rxbuf_consumed				renamed_iip_tcp_rxbuf_consumed
#define iip_tcp_close					renamed_iip_tcp_close
#define iip_tcp_send					renamed_iip_tcp_send
#define iip_arp_request					renamed_iip_arp_request
#define iip_add_tcp_conn				renamed_iip_add_tcp_conn
#define iip_add_pb					renamed_iip_add_pb
#define iip_tcp_conn_size				renamed_iip_tcp_conn_size
#define iip_pb_size					renamed_iip_pb_size
#define iip_workspace_size				renamed_iip_workspace_size

#include "../iip/main.c"

#undef iip_run
#undef iip_udp_send
#undef iip_tcp_connect
#undef iip_tcp_rxbuf_consumed
#undef iip_tcp_close
#undef iip_tcp_send
#undef iip_arp_request
#undef iip_add_tcp_conn
#undef iip_add_pb
#undef iip_tcp_conn_size
#undef iip_pb_size
#undef iip_workspace_size

#undef iip_ops_pkt_alloc
#undef iip_ops_pkt_free
#undef iip_ops_pkt_get_data
#undef iip_ops_pkt_get_len
#undef iip_ops_pkt_set_len
#undef iip_ops_pkt_increment_head
#undef iip_ops_pkt_decrement_tail
#undef iip_ops_pkt_clone
#undef iip_ops_pkt_scatter_gather_chain_append
#undef iip_ops_pkt_scatter_gather_chain_get_next
#undef iip_ops_l2_hdr_len
#undef iip_ops_l2_hdr_src_ptr
#undef iip_ops_l2_hdr_dst_ptr
#undef iip_ops_l2_ethertype_be
#undef iip_ops_l2_addr_len
#undef iip_ops_l2_broadcast_addr
#undef iip_ops_l2_hdr_craft
#undef iip_ops_l2_skip
#undef iip_ops_l2_flush
#undef iip_ops_l2_push
#undef iip_ops_arp_lhw
#undef iip_ops_arp_lproto
#undef iip_ops_arp_reply
#undef iip_ops_icmp_reply
#undef iip_ops_tcp_accept
#undef iip_ops_tcp_accepted
#undef iip_ops_tcp_connected
#undef iip_ops_tcp_closed
#undef iip_ops_tcp_payload
#undef iip_ops_tcp_acked
#undef iip_ops_udp_payload
#undef iip_ops_nic_feature_offload_tx_scatter_gather
#undef iip_ops_nic_feature_offload_ip4_rx_checksum
#undef iip_ops_nic_feature_offload_ip4_tx_checksum
#undef iip_ops_nic_feature_offload_tcp_rx_checksum
#undef iip_ops_nic_feature_offload_tcp_tx_checksum
#undef iip_ops_nic_feature_offload_tcp_tx_tso
#undef iip_ops_nic_feature_offload_udp_rx_checksum
#undef iip_ops_nic_feature_offload_udp_tx_checksum
#undef iip_ops_nic_feature_offload_udp_tx_tso
#undef iip_ops_nic_offload_ip4_rx_checksum
#undef iip_ops_nic_offload_udp_rx_checksum
#undef iip_ops_nic_offload_tcp_rx_checksum
#undef iip_ops_nic_offload_ip4_tx_checksum_mark
#undef iip_ops_nic_offload_tcp_tx_checksum_mark
#undef iip_ops_nic_offload_tcp_tx_tso_mark
#undef iip_ops_nic_offload_udp_tx_checksum_mark
#undef iip_ops_nic_offload_udp_tx_tso_mark
#undef iip_ops_util_now_ns

extern long MPK_IIP_OPS_pkt_alloc(long, ...);
extern long MPK_IIP_OPS_pkt_free(long, ...);
extern long MPK_IIP_OPS_pkt_get_data(long, ...);
extern long MPK_IIP_OPS_pkt_get_len(long, ...);
extern long MPK_IIP_OPS_pkt_set_len(long, ...);
extern long MPK_IIP_OPS_pkt_increment_head(long, ...);
extern long MPK_IIP_OPS_pkt_decrement_tail(long, ...);
extern long MPK_IIP_OPS_pkt_clone(long, ...);
extern long MPK_IIP_OPS_pkt_scatter_gather_chain_append(long, ...);
extern long MPK_IIP_OPS_pkt_scatter_gather_chain_get_next(long, ...);
extern long MPK_IIP_OPS_l2_hdr_len(long, ...);
extern long MPK_IIP_OPS_l2_hdr_src_ptr(long, ...);
extern long MPK_IIP_OPS_l2_hdr_dst_ptr(long, ...);
extern long MPK_IIP_OPS_l2_ethertype_be(long, ...);
extern long MPK_IIP_OPS_l2_addr_len(long, ...);
extern long MPK_IIP_OPS_l2_broadcast_addr(long, ...);
extern long MPK_IIP_OPS_l2_hdr_craft(long, ...);
extern long MPK_IIP_OPS_l2_skip(long, ...);
extern long MPK_IIP_OPS_l2_flush(long, ...);
extern long MPK_IIP_OPS_l2_push(long, ...);
extern long MPK_IIP_OPS_arp_lhw(long, ...);
extern long MPK_IIP_OPS_arp_lproto(long, ...);
extern long MPK_IIP_OPS_arp_reply(long, ...);
extern long MPK_IIP_OPS_icmp_reply(long, ...);
extern long MPK_IIP_OPS_tcp_accept(long, ...);
extern long MPK_IIP_OPS_tcp_accepted(long, ...);
extern long MPK_IIP_OPS_tcp_connected(long, ...);
extern long MPK_IIP_OPS_tcp_closed(long, ...);
extern long MPK_IIP_OPS_tcp_payload(long, ...);
extern long MPK_IIP_OPS_tcp_acked(long, ...);
extern long MPK_IIP_OPS_udp_payload(long, ...);
extern long MPK_IIP_OPS_nic_feature_offload_tx_scatter_gather(long, ...);
extern long MPK_IIP_OPS_nic_feature_offload_ip4_rx_checksum(long, ...);
extern long MPK_IIP_OPS_nic_feature_offload_ip4_tx_checksum(long, ...);
extern long MPK_IIP_OPS_nic_feature_offload_tcp_rx_checksum(long, ...);
extern long MPK_IIP_OPS_nic_feature_offload_tcp_tx_checksum(long, ...);
extern long MPK_IIP_OPS_nic_feature_offload_tcp_tx_tso(long, ...);
extern long MPK_IIP_OPS_nic_feature_offload_udp_rx_checksum(long, ...);
extern long MPK_IIP_OPS_nic_feature_offload_udp_tx_checksum(long, ...);
extern long MPK_IIP_OPS_nic_feature_offload_udp_tx_tso(long, ...);
extern long MPK_IIP_OPS_nic_offload_ip4_rx_checksum(long, ...);
extern long MPK_IIP_OPS_nic_offload_udp_rx_checksum(long, ...);
extern long MPK_IIP_OPS_nic_offload_tcp_rx_checksum(long, ...);
extern long MPK_IIP_OPS_nic_offload_ip4_tx_checksum_mark(long, ...);
extern long MPK_IIP_OPS_nic_offload_tcp_tx_checksum_mark(long, ...);
extern long MPK_IIP_OPS_nic_offload_tcp_tx_tso_mark(long, ...);
extern long MPK_IIP_OPS_nic_offload_udp_tx_checksum_mark(long, ...);
extern long MPK_IIP_OPS_nic_offload_udp_tx_tso_mark(long, ...);
extern long MPK_IIP_OPS_util_now_ns(long, ...);
extern long MPK_IIP_OPS_BATCHED_l2_flush(long, ...);
extern long MPK_IIP_OPS_BATCHED_tcp_input(long, ...);

#include "side-both.c"

#define MPKTBUF_IDX(__mem, __mpktbuf, __is_large) \
	({ \
		uint32_t ret; \
		if ((uintptr_t) (__mpktbuf) < (uintptr_t) MPKTBUF(__mem, NUM_MPKT_BUF)) { \
			ret = (((uintptr_t) (__mpktbuf) - (uintptr_t) MPKTBUF(__mem, 0)) / MPKTBUF_LEN); \
			(__is_large) = 0; \
			(void) (__is_large); \
		} else { \
			ret = (((uintptr_t) (__mpktbuf) - (uintptr_t) MPKTBUF_LARGE(__mem, 0)) / MPKTBUF_LARGE_LEN); \
			(__is_large) = 1; \
			(void) (__is_large); \
		} \
		ret; \
	})

#define iip_mpk_memory_copy_64b(__pkru, __dst, __src, __len, __copy_out) \
	do { \
		uint32_t ____l = 0; \
		while (____l < (uint32_t) (__len)) { \
			uint32_t ____ll = (uint32_t) (__len) - ____l; \
			if (____ll > 2048) { \
				____ll = 2048; \
			} \
			zmm_memcpy_64b(__pkru, ((void *)__dst) + ____l, ((void *)__src) + ____l, ____ll, __copy_out); \
			____l += ____ll; \
		} \
	} while (0)

struct mpk_opaque {
	long orig_pkru;
	long orig_stack;
	void *workspace;
	void *opaque;
	uint32_t now[3];
};

static void *__MPK_iip_ops_pkt_alloc(void *opaque)
{
	return (void *) mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long)((struct mpk_opaque *) opaque)->opaque, 0, 0, MPK_IIP_OPS_pkt_alloc);
}

static void __MPK_iip_ops_pkt_free(void *pkt, void *opaque)
{
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long) pkt, (long) ((struct mpk_opaque *) opaque)->opaque, 0, MPK_IIP_OPS_pkt_free);
}

static void *__MPK_iip_ops_pkt_get_data(void *pkt, void *opaque)
{
	return (void *) mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long) pkt, (long) ((struct mpk_opaque *) opaque)->opaque, 0, MPK_IIP_OPS_pkt_get_data);
}

static uint16_t __MPK_iip_ops_pkt_get_len(void *pkt, void *opaque)
{
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long) pkt, (long) ((struct mpk_opaque *) opaque)->opaque, 0, MPK_IIP_OPS_pkt_get_len);
}

static void __MPK_iip_ops_pkt_set_len(void *pkt, uint16_t len, void *opaque)
{
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long) pkt, len, (long) ((struct mpk_opaque *) opaque)->opaque, MPK_IIP_OPS_pkt_set_len);
}

static void __MPK_iip_ops_pkt_increment_head(void *pkt, uint16_t len, void *opaque)
{
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long) pkt, len, (long) ((struct mpk_opaque *) opaque)->opaque, MPK_IIP_OPS_pkt_increment_head);
}

static void __MPK_iip_ops_pkt_decrement_tail(void *pkt, uint16_t len, void *opaque)
{
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long) pkt, len, (long) ((struct mpk_opaque *) opaque)->opaque, MPK_IIP_OPS_pkt_decrement_tail);
}

static void *__MPK_iip_ops_pkt_clone(void *pkt, void *opaque)
{
	return (void *) mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long) pkt, (long) ((struct mpk_opaque *) opaque)->opaque, 0, MPK_IIP_OPS_pkt_clone);
}

static void __MPK_iip_ops_pkt_scatter_gather_chain_append(void *pkt_head, void *pkt_tail, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) pkt_head;
		arg[2] = (long) pkt_tail;
		arg[3] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0,
		MPK_IIP_OPS_pkt_scatter_gather_chain_append);
}

static void *__MPK_iip_ops_pkt_scatter_gather_chain_get_next(void *pkt_head, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) pkt_head;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return (void *) mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_pkt_scatter_gather_chain_get_next);
}

static void __MPK_iip_ops_util_now_ns(uint32_t t[3], void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long t_buf[8] __attribute__((aligned(64)));
		{
			long arg[8] __attribute__((aligned(64))) = { 0 };
			arg[1] = (long) t_buf;
			arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
			rsp -= sizeof(arg);
			iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
		}
		mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_util_now_ns);
		__iip_memcpy(t, t_buf, sizeof(uint32_t) * 3);
	}
}

static uint16_t __MPK_iip_ops_l2_hdr_len(void *pkt, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) pkt;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_l2_hdr_len);
}

static uint8_t *__MPK_iip_ops_l2_hdr_src_ptr(void *pkt, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) pkt;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return (void *) mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_l2_hdr_src_ptr);
}

static uint8_t *__MPK_iip_ops_l2_hdr_dst_ptr(void *pkt, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) pkt;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return (void *) mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_l2_hdr_dst_ptr);
}

static uint16_t __MPK_iip_ops_l2_ethertype_be(void *pkt, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) pkt;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_l2_ethertype_be);
}

static uint16_t __MPK_iip_ops_l2_addr_len(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_l2_addr_len);
}

static void __MPK_iip_ops_l2_broadcast_addr(uint8_t bcaddr[], void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long bcaddr_buf[256] __attribute__((aligned(64)));;
		{
			uint16_t l = __MPK_iip_ops_l2_addr_len(opaque);
			__iip_memset(bcaddr_buf, 0, (l % 32 ? (l / 32 + 1) * 32 : l));
			{
				long arg[8] __attribute__((aligned(64))) = { 0 };
				arg[1] = (long) bcaddr_buf;
				arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
				rsp -= sizeof(arg);
				iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
			}
			mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_l2_broadcast_addr);
			__iip_memcpy(bcaddr, bcaddr_buf, l);
		}
	}
}

static void __MPK_iip_ops_l2_hdr_craft(void *pkt, uint8_t src[], uint8_t dst[], uint16_t ethertype_be, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		void *__src, *__dst;
		{
			uint16_t l = __MPK_iip_ops_l2_addr_len(opaque), _l = l;
			l = l % 64 ? (l / 64 + 1) * 64 : l;
			rsp -= l;
			__src = (void *) rsp;
			{
				uint8_t tmp[0xffff] __attribute__((aligned(64)));
				__iip_memcpy(tmp, src, _l);
				iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, __src, (void *) tmp, _l, 1);
			}
			rsp -= l;
			__dst = (void *) rsp;
			{
				uint8_t tmp[0xffff] __attribute__((aligned(64)));
				__iip_memcpy(tmp, dst, _l);
				iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, __dst, (void *) tmp, _l, 1);
			}
		}
		{
			long arg[8] __attribute__((aligned(64))) = { 0 };
			arg[1] = (long) pkt;
			arg[2] = (long) __src;
			arg[3] = (long) __dst;
			arg[4] = ethertype_be;
			arg[5] = (long) ((struct mpk_opaque *) opaque)->opaque;
			rsp -= sizeof(arg);
			iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
		}
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_l2_hdr_craft);
}

static uint8_t __MPK_iip_ops_l2_skip(void *pkt, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) pkt;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_l2_skip);
}

static void __MPK_iip_ops_l2_flush(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_l2_flush);
}

static void __MPK_iip_ops_l2_push(void *_m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) _m;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_l2_push);
}

static uint8_t __MPK_iip_ops_nic_feature_offload_tx_scatter_gather(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_feature_offload_tx_scatter_gather);
}

static uint8_t __MPK_iip_ops_nic_feature_offload_ip4_rx_checksum(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_feature_offload_ip4_rx_checksum);
}

static uint8_t __MPK_iip_ops_nic_feature_offload_ip4_tx_checksum(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0,
		MPK_IIP_OPS_nic_feature_offload_ip4_tx_checksum);
}

static uint8_t __MPK_iip_ops_nic_offload_ip4_rx_checksum(void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) m;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_offload_ip4_rx_checksum);
}

static uint8_t __MPK_iip_ops_nic_offload_tcp_rx_checksum(void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) m;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_offload_tcp_rx_checksum);
}

static uint8_t __MPK_iip_ops_nic_offload_udp_rx_checksum(void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) m;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_offload_udp_rx_checksum);
}

static void __MPK_iip_ops_nic_offload_ip4_tx_checksum_mark(void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) m;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_offload_ip4_tx_checksum_mark);
}

static uint8_t __MPK_iip_ops_nic_feature_offload_tcp_rx_checksum(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_feature_offload_tcp_rx_checksum);
}

static uint8_t __MPK_iip_ops_nic_feature_offload_tcp_tx_checksum(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_feature_offload_tcp_tx_checksum);
}

static uint8_t __MPK_iip_ops_nic_feature_offload_tcp_tx_tso(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_feature_offload_tcp_tx_tso);
}

static void __MPK_iip_ops_nic_offload_tcp_tx_checksum_mark(void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) m;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_offload_tcp_tx_checksum_mark);
}

static void __MPK_iip_ops_nic_offload_tcp_tx_tso_mark(void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) m;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_offload_tcp_tx_tso_mark);
}

static uint8_t __MPK_iip_ops_nic_feature_offload_udp_rx_checksum(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_feature_offload_udp_rx_checksum);
}

static uint8_t __MPK_iip_ops_nic_feature_offload_udp_tx_checksum(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_feature_offload_udp_tx_checksum);
}

static uint8_t __MPK_iip_ops_nic_feature_offload_udp_tx_tso(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_feature_offload_udp_tx_tso);
}

static void __MPK_iip_ops_nic_offload_udp_tx_checksum_mark(void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) m;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_offload_udp_tx_checksum_mark);
}

static void __MPK_iip_ops_nic_offload_udp_tx_tso_mark(void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) m;
		arg[2] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_nic_offload_udp_tx_tso_mark);
}

static uint8_t __MPK_iip_ops_arp_lhw(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_arp_lhw);
}

static uint8_t __MPK_iip_ops_arp_lproto(void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_arp_lproto);
}

static void __MPK_iip_ops_arp_reply(void *_mem, void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) _mem;
		arg[2] = (long) m;
		arg[3] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_arp_reply);
}

static void __MPK_iip_ops_icmp_reply(void *_mem, void *m, void *opaque)
{
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long) _mem, (long) m, (long) ((struct mpk_opaque *) opaque)->opaque, MPK_IIP_OPS_icmp_reply);
}

static uint8_t __MPK_iip_ops_tcp_accept(void *mem, void *m, void *opaque)
{
	return mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long) mem, (long) m, (long) ((struct mpk_opaque *) opaque)->opaque, MPK_IIP_OPS_tcp_accept);
}

static void *__MPK_iip_ops_tcp_accepted(void *mem, void *handle, void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) mem;
		arg[2] = (long) handle;
		arg[3] = (long) m;
		arg[4] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return (void *) mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_tcp_accepted);
}

static void *__MPK_iip_ops_tcp_connected(void *mem, void *handle, void *m, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) mem;
		arg[2] = (long) handle;
		arg[3] = (long) m;
		arg[4] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	return (void *) mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_tcp_connected);
}

static void __MPK_iip_ops_tcp_payload(void *mem, void *handle, void *m, void *tcp_opaque, uint16_t head_off, uint16_t tail_off, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) mem;
		arg[2] = (long) handle;
		arg[3] = (long) m;
		arg[4] = (long) tcp_opaque;
		arg[5] = head_off;
		arg[6] = tail_off;
		arg[7] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_tcp_payload);
}

static void __MPK_iip_ops_tcp_acked(void *mem, void *handle, void *m, void *tcp_opaque, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		long arg[8] __attribute__((aligned(64))) = { 0 };
		arg[1] = (long) mem;
		arg[2] = (long) handle;
		arg[3] = (long) m;
		arg[4] = (long) tcp_opaque;
		arg[5] = (long) ((struct mpk_opaque *) opaque)->opaque;
		rsp -= sizeof(arg);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_tcp_acked);
}

static void __MPK_iip_ops_tcp_closed(void *handle, uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be, uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be, void *tcp_opaque, void *opaque)
{
	long rsp = ((struct mpk_opaque *) opaque)->orig_stack;
	{
		void *__local_mac, *__peer_mac;
		{
			uint16_t l = __MPK_iip_ops_l2_addr_len(opaque), _l = l;
			l = l % 64 ? (l / 64 + 1) * 64 : l;
			rsp -= l;
			__local_mac = (void *) rsp;
			{
				uint8_t tmp[0xffff] __attribute__((aligned(64)));
				__iip_memcpy(tmp, local_mac, _l);
				iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, __local_mac, (void *) tmp, _l, 1);
			}
			rsp -= l;
			__peer_mac = (void *) rsp;
			{
				uint8_t tmp[0xffff] __attribute__((aligned(64)));
				__iip_memcpy(tmp, peer_mac, _l);
				iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, __peer_mac, (void *) tmp, _l, 1);
			}
		}
		{
			long arg[16] __attribute__((aligned(64))) = { 0 };
			arg[0] = (long) ((struct mpk_opaque *) opaque)->workspace;
			arg[1] = (long) handle;
			arg[2] = (long) __local_mac;
			arg[3] = local_ip4_be;
			arg[4] = local_port_be;
			arg[5] = (long) __peer_mac;
			arg[6] = peer_ip4_be;
			arg[7] = peer_port_be;
			arg[8] = (long) tcp_opaque;
			arg[9] = (long) ((struct mpk_opaque *) opaque)->opaque;
			rsp -= sizeof(arg);
			iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp, (void *) arg, sizeof(arg), 1);
		}
	}
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_tcp_closed);
}

static void __MPK_iip_ops_udp_payload(void *mem, void *m, void *opaque)
{
	mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, ((struct mpk_opaque *) opaque)->orig_stack, (long) mem, (long) m, (long) ((struct mpk_opaque *) opaque)->opaque, MPK_IIP_OPS_udp_payload);
}

static void *renamed_iip_ops_pkt_alloc(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	__iip_assert(mm->mpkt_queue.cnt);
	__iip_assert(mm->mpktbuf_queue.cnt);
	{
		struct mpkt *mpkt = mm->mpkt_queue.p[--mm->mpkt_queue.cnt];
		mpkt->data = mm->mpktbuf_queue.p[--mm->mpktbuf_queue.cnt];
		{
			char is_large = 0;
			mm->mpktbuf_queue.ref[MPKTBUF_IDX(((struct mpk_opaque *) opaque)->workspace, mpkt->data, is_large)] = 1;
		}
		return (void *) mpkt;
	}
}

static void *__iip_ops_pkt_alloc_large(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	__iip_assert(mm->mpkt_queue.cnt);
	__iip_assert(mm->mpktbuf_large_queue.cnt);
	{
		struct mpkt *mpkt = mm->mpkt_queue.p[--mm->mpkt_queue.cnt];
		mpkt->data = mm->mpktbuf_large_queue.p[--mm->mpktbuf_large_queue.cnt];
		{
			char is_large = 0;
			mm->mpktbuf_large_queue.ref[MPKTBUF_IDX(((struct mpk_opaque *) opaque)->workspace, mpkt->data, is_large)] = 1;
		}
		return (void *) mpkt;
	}
}

static void renamed_iip_ops_pkt_free(void *pkt, void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	{
		struct mpkt *m = (struct mpkt *) pkt;
		while (m) {
			struct mpkt *next = m->next;
			{
				char is_large = 0;
				uint32_t idx = MPKTBUF_IDX(((struct mpk_opaque *) opaque)->workspace, ((struct mpkt *) m)->data, is_large);
				if (!is_large) {
					if (--mm->mpktbuf_queue.ref[idx] == 0)
						mm->mpktbuf_queue.p[mm->mpktbuf_queue.cnt++] = ((struct mpkt *) m)->data;
				} else {
					if (--mm->mpktbuf_large_queue.ref[idx] == 0)
						mm->mpktbuf_large_queue.p[mm->mpktbuf_large_queue.cnt++] = ((struct mpkt *) m)->data;
				}
				if (m->rx_pkt)
					__MPK_iip_ops_pkt_free(m->rx_pkt, opaque);
				__iip_memset(m, 0, sizeof(struct mpkt));
				mm->mpkt_queue.p[mm->mpkt_queue.cnt++] = (struct mpkt *) m;
			}
			m = next;
		}
	}
}

static void *renamed_iip_ops_pkt_get_data(void *pkt, void *opaque)
{
	return &((struct mpkt *) pkt)->data[((struct mpkt *) pkt)->head];
	{ /* unused */
		(void) opaque;
	}
}

static uint16_t renamed_iip_ops_pkt_get_len(void *pkt, void *opaque)
{
	return (uint16_t) ((struct mpkt *) pkt)->len;
	{ /* unused */
		(void) opaque;
	}
}

static void renamed_iip_ops_pkt_set_len(void *pkt, uint16_t len, void *opaque)
{
	((struct mpkt *) pkt)->len = len;
	{ /* unused */
		(void) opaque;
	}
}

static void renamed_iip_ops_pkt_increment_head(void *pkt, uint16_t len, void *opaque)
{
	((struct mpkt *) pkt)->head += len;
	{ /* unused */
		(void) opaque;
	}
}

static void renamed_iip_ops_pkt_decrement_tail(void *pkt, uint16_t len, void *opaque)
{
	((struct mpkt *) pkt)->len -= len;
	{ /* unused */
		(void) opaque;
	}
}

static void *renamed_iip_ops_pkt_clone(void *pkt, void *opaque)
{
	void *head = NULL;
	{
		struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
		{
			struct mpkt *m = (struct mpkt *) pkt;
			while (m) {
				__iip_assert(mm->mpkt_queue.cnt);
				{
					struct mpkt *mpkt = mm->mpkt_queue.p[--mm->mpkt_queue.cnt];
					__iip_memcpy(mpkt, m, sizeof(struct mpkt));
					{
						char is_large = 0;
						mm->mpktbuf_queue.ref[MPKTBUF_IDX(((struct mpk_opaque *) opaque)->workspace, mpkt->data, is_large)]++;
					}
					mpkt->rx_pkt = NULL; /* XXX: rx_pkt is associated only with the original one */
					mpkt->next = NULL;
					if (head)
						renamed_iip_ops_pkt_scatter_gather_chain_append(head, (void *) mpkt, opaque);
					else
						head = mpkt;
				}
				m = m->next;
			}
		}
	}
	__iip_assert(head);
	return head;
}

static void renamed_iip_ops_pkt_scatter_gather_chain_append(void *pkt_head, void *pkt_tail, void *opaque)
{
	struct mpkt *mpkt = (struct mpkt *) pkt_head;
	while (mpkt->next) mpkt = mpkt->next;
	mpkt->next = (struct mpkt *) pkt_tail;
	{ /* unused */
		(void) opaque;
	}
}

static void *renamed_iip_ops_pkt_scatter_gather_chain_get_next(void *pkt_head, void *opaque)
{
	return ((struct mpkt *) pkt_head)->next;
	{ /* unused */
		(void) opaque;
	}
}

static void renamed_iip_ops_util_now_ns(uint32_t t[3], void *opaque)
{
	__iip_memcpy(t, ((struct mpk_opaque *) opaque)->now, sizeof(uint32_t) * 3);
}

static uint16_t renamed_iip_ops_l2_hdr_len(void *pkt, void *opaque)
{
	return 14; /* XXX: specific to ethernet */
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint8_t *renamed_iip_ops_l2_hdr_src_ptr(void *pkt, void *opaque)
{
	return &((uint8_t *) renamed_iip_ops_pkt_get_data(pkt, opaque))[6]; /* XXX: specific to ethernet */
}

static uint8_t *renamed_iip_ops_l2_hdr_dst_ptr(void *pkt, void *opaque)
{
	return &((uint8_t *) renamed_iip_ops_pkt_get_data(pkt, opaque))[0]; /* XXX: specific to ethernet */
}

static uint16_t renamed_iip_ops_l2_ethertype_be(void *pkt, void *opaque)
{
	return *((uint16_t *) &((uint8_t *) renamed_iip_ops_pkt_get_data(pkt, opaque))[12]); /* XXX: specific to ethernet */
}

static uint16_t renamed_iip_ops_l2_addr_len(void *opaque)
{
	return 6; /* XXX: specific to ethernet */
	{ /* unused */
		(void) opaque;
	}
}

static void renamed_iip_ops_l2_broadcast_addr(uint8_t bcaddr[], void *opaque)
{
	__iip_memset(bcaddr, 0xff, 6); /* XXX: specific to ethernet */
	{ /* unused */
		(void) opaque;
	}
}

static void renamed_iip_ops_l2_hdr_craft(void *pkt, uint8_t src[], uint8_t dst[], uint16_t ethertype_be, void *opaque)
{
	/* XXX: specific to ethernet */
	__iip_memcpy(renamed_iip_ops_l2_hdr_src_ptr(pkt, opaque), src, renamed_iip_ops_l2_addr_len(opaque));
	__iip_memcpy(renamed_iip_ops_l2_hdr_dst_ptr(pkt, opaque), dst, renamed_iip_ops_l2_addr_len(opaque));
	*((uint16_t *) &((uint8_t *) renamed_iip_ops_pkt_get_data(pkt, opaque))[12]) = ethertype_be;
}

static uint8_t renamed_iip_ops_l2_skip(void *pkt, void *opaque)
{
	return (((struct mpkt *) pkt)->rx_flags & (1U << 0)) ? 1 : 0;
	{ /* unused */
		(void) opaque;
	}
}

static void renamed_iip_ops_l2_flush(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	if (mm->tx_queue.total) {
		long rsp = ((struct mpk_opaque *) opaque)->orig_stack - mm->tx_queue.total * 64;
		{
			long _arg[256] __attribute__((aligned(64))) = { 0 }, *arg = _arg, copied = 0;
			{
				uint32_t i;
				for (i = 0; i < mm->tx_queue.cnt; i++) {
					struct mpkt *m = mm->tx_queue.p[i];
					while (m) {
						arg[1] = (long) renamed_iip_ops_pkt_get_data((void *) m, opaque);
						arg[2] = renamed_iip_ops_pkt_get_len((void *) m, opaque);
						arg[3] = m->tx_flags;
						arg[4] = (m->next ? 1 : 0);
						arg[5] = (long) ((struct mpk_opaque *) opaque)->opaque;
						if (!__EXPERIMENT_NO_MEMCOPYSKIP
								&& renamed_iip_ops_nic_feature_offload_tx_scatter_gather(opaque))
							arg[6] = (long) m->tx_pkt;
						arg[7] = m->head;
						m = m->next;
						arg = &arg[8];
						if (arg == &_arg[256]) {
							iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp + copied, (void *) _arg, sizeof(_arg), 1);
							copied += sizeof(_arg);
							arg = _arg;
						}
					}
				}
				if (arg != _arg)
					iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp + copied, (void *) _arg, (uintptr_t) arg - (uintptr_t) _arg, 1);
			}
		}
		mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, rsp, mm->tx_queue.cnt, (long) ((struct mpk_opaque *) opaque)->opaque, MPK_IIP_OPS_BATCHED_l2_flush);
		{
			uint32_t i;
			for (i = 0; i < mm->tx_queue.cnt; i++)
				renamed_iip_ops_pkt_free(mm->tx_queue.p[i], opaque);
		}
		mm->tx_queue.total = mm->tx_queue.cnt = 0;
	}
}

static void renamed_iip_ops_l2_push(void *_m, void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	__iip_assert(mm->tx_queue.cnt < NUM_MPKT);
	mm->tx_queue.p[mm->tx_queue.cnt++] = _m;
	{
		struct mpkt *m = (struct mpkt *) _m;
		while (m) {
			mm->tx_queue.total++;
			m = m->next;
		}
	}
}

static uint8_t renamed_iip_ops_nic_feature_offload_tx_scatter_gather(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	if (!mm->nic_feature.offload_tx_scatter_gather) {
		long ret = __MPK_iip_ops_nic_feature_offload_tx_scatter_gather(opaque);
		if (ret)
			mm->nic_feature.offload_tx_scatter_gather = 1;
		else
			mm->nic_feature.offload_tx_scatter_gather = 2;
	}
	return (mm->nic_feature.offload_tx_scatter_gather == 1 ? 1 : 0);
}

static uint8_t renamed_iip_ops_nic_feature_offload_ip4_rx_checksum(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	if (!mm->nic_feature.offload_ip4_rx_checksum) {
		long ret = __MPK_iip_ops_nic_feature_offload_ip4_rx_checksum(opaque);
		if (ret)
			mm->nic_feature.offload_ip4_rx_checksum = 1;
		else
			mm->nic_feature.offload_ip4_rx_checksum = 2;
	}
	return (mm->nic_feature.offload_ip4_rx_checksum == 1 ? 1 : 0);
}

static uint8_t renamed_iip_ops_nic_feature_offload_ip4_tx_checksum(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	if (!mm->nic_feature.offload_ip4_tx_checksum) {
		long ret = __MPK_iip_ops_nic_feature_offload_ip4_tx_checksum(opaque);
		if (ret)
			mm->nic_feature.offload_ip4_tx_checksum = 1;
		else
			mm->nic_feature.offload_ip4_tx_checksum = 2;
	}
	return (mm->nic_feature.offload_ip4_tx_checksum == 1 ? 1 : 0);
}

static uint8_t renamed_iip_ops_nic_offload_ip4_rx_checksum(void *m, void *opaque)
{
	return (((struct mpkt *) m)->rx_flags & (1U << 1)) ? 1 : 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t renamed_iip_ops_nic_offload_tcp_rx_checksum(void *m, void *opaque)
{
	return (((struct mpkt *) m)->rx_flags & (1U << 2)) ? 1 : 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t renamed_iip_ops_nic_offload_udp_rx_checksum(void *m, void *opaque)
{
	return (((struct mpkt *) m)->rx_flags & (1U << 3)) ? 1 : 0;
	{ /* unused */
		(void) opaque;
	}
}

static void renamed_iip_ops_nic_offload_ip4_tx_checksum_mark(void *m, void *opaque)
{
	((struct mpkt *) m)->tx_flags |= (1U << 1);
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t renamed_iip_ops_nic_feature_offload_tcp_rx_checksum(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	if (!mm->nic_feature.offload_tcp_rx_checksum) {
		long ret = __MPK_iip_ops_nic_feature_offload_tcp_rx_checksum(opaque);
		if (ret)
			mm->nic_feature.offload_tcp_rx_checksum = 1;
		else
			mm->nic_feature.offload_tcp_rx_checksum = 2;
	}
	return (mm->nic_feature.offload_tcp_rx_checksum == 1 ? 1 : 0);
}

static uint8_t renamed_iip_ops_nic_feature_offload_tcp_tx_checksum(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	if (!mm->nic_feature.offload_tcp_tx_checksum) {
		long ret = __MPK_iip_ops_nic_feature_offload_tcp_tx_checksum(opaque);
		if (ret)
			mm->nic_feature.offload_tcp_tx_checksum = 1;
		else
			mm->nic_feature.offload_tcp_tx_checksum = 2;
	}
	return (mm->nic_feature.offload_tcp_tx_checksum == 1 ? 1 : 0);
}

static uint8_t renamed_iip_ops_nic_feature_offload_tcp_tx_tso(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	if (!mm->nic_feature.offload_tcp_tx_tso) {
		long ret = __MPK_iip_ops_nic_feature_offload_tcp_tx_tso(opaque);
		if (ret)
			mm->nic_feature.offload_tcp_tx_tso = 1;
		else
			mm->nic_feature.offload_tcp_tx_tso = 2;
	}
	return (mm->nic_feature.offload_tcp_tx_tso == 1 ? 1 : 0);
}

static void renamed_iip_ops_nic_offload_tcp_tx_checksum_mark(void *m, void *opaque)
{
	((struct mpkt *) m)->tx_flags |= (1U << 2);
	{ /* unused */
		(void) opaque;
	}
}

static void renamed_iip_ops_nic_offload_tcp_tx_tso_mark(void *m, void *opaque)
{
	((struct mpkt *) m)->tx_flags |= (1U << 3);
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t renamed_iip_ops_nic_feature_offload_udp_rx_checksum(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	if (!mm->nic_feature.offload_udp_rx_checksum) {
		long ret = __MPK_iip_ops_nic_feature_offload_udp_rx_checksum(opaque);
		if (ret)
			mm->nic_feature.offload_udp_rx_checksum = 1;
		else
			mm->nic_feature.offload_udp_rx_checksum = 2;
	}
	return (mm->nic_feature.offload_udp_rx_checksum == 1 ? 1 : 0);
}

static uint8_t renamed_iip_ops_nic_feature_offload_udp_tx_checksum(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	if (!mm->nic_feature.offload_udp_tx_checksum) {
		long ret = __MPK_iip_ops_nic_feature_offload_udp_tx_checksum(opaque);
		if (ret)
			mm->nic_feature.offload_udp_tx_checksum = 1;
		else
			mm->nic_feature.offload_udp_tx_checksum = 2;
	}
	return (mm->nic_feature.offload_udp_tx_checksum == 1 ? 1 : 0);
}

static uint8_t renamed_iip_ops_nic_feature_offload_udp_tx_tso(void *opaque)
{
	struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
	if (!mm->nic_feature.offload_udp_tx_tso) {
		long ret = __MPK_iip_ops_nic_feature_offload_udp_tx_tso(opaque);
		if (ret)
			mm->nic_feature.offload_udp_tx_tso = 1;
		else
			mm->nic_feature.offload_udp_tx_tso = 2;
	}
	return (mm->nic_feature.offload_udp_tx_tso == 1 ? 1 : 0);
}

static void renamed_iip_ops_nic_offload_udp_tx_checksum_mark(void *m, void *opaque)
{
	((struct mpkt *) m)->tx_flags |= (1U << 4);
	{ /* unused */
		(void) opaque;
	}
}

static void renamed_iip_ops_nic_offload_udp_tx_tso_mark(void *m, void *opaque)
{
	((struct mpkt *) m)->tx_flags |= (1U << 5);
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t renamed_iip_ops_arp_lhw(void *opaque)
{
	return __MPK_iip_ops_arp_lhw(opaque);
}

static uint8_t renamed_iip_ops_arp_lproto(void *opaque)
{
	return __MPK_iip_ops_arp_lproto(opaque);
}

static void renamed_iip_ops_arp_reply(void *_mem, void *m, void *opaque)
{
	void *pkt = __MPK_iip_ops_pkt_alloc(opaque);
	__iip_assert(pkt);
	iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, __MPK_iip_ops_pkt_get_data(pkt, opaque), renamed_iip_ops_pkt_get_data(m, opaque), renamed_iip_ops_pkt_get_len(m, opaque), 1);
	__MPK_iip_ops_pkt_set_len(pkt, renamed_iip_ops_pkt_get_len(m, opaque), opaque);
	__MPK_iip_ops_arp_reply(_mem, pkt, opaque);
	__MPK_iip_ops_pkt_free(pkt, opaque);
}

static void renamed_iip_ops_icmp_reply(void *_mem, void *m, void *opaque)
{
	void *pkt = __MPK_iip_ops_pkt_alloc(opaque);
	__iip_assert(pkt);
	iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, __MPK_iip_ops_pkt_get_data(pkt, opaque), renamed_iip_ops_pkt_get_data(m, opaque), renamed_iip_ops_pkt_get_len(m, opaque), 1);
	__MPK_iip_ops_pkt_set_len(pkt, renamed_iip_ops_pkt_get_len(m, opaque), opaque);
	__MPK_iip_ops_icmp_reply(_mem, pkt, opaque);
	__MPK_iip_ops_pkt_free(pkt, opaque);
}

static uint8_t renamed_iip_ops_tcp_accept(void *mem, void *m, void *opaque)
{
	uint8_t ret;
	{
		void *pkt = __MPK_iip_ops_pkt_alloc(opaque);
		__iip_assert(pkt);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, __MPK_iip_ops_pkt_get_data(pkt, opaque), renamed_iip_ops_pkt_get_data(m, opaque), renamed_iip_ops_pkt_get_len(m, opaque), 1);
		__MPK_iip_ops_pkt_set_len(pkt, renamed_iip_ops_pkt_get_len(m, opaque), opaque);
		ret = __MPK_iip_ops_tcp_accept(mem, pkt, opaque);
		__MPK_iip_ops_pkt_free(pkt, opaque);
	}
	return ret;
}

static void *renamed_iip_ops_tcp_accepted(void *mem, void *handle, void *m, void *opaque)
{
	void *ret;
	{
		void *pkt = __MPK_iip_ops_pkt_alloc(opaque);
		__iip_assert(pkt);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, __MPK_iip_ops_pkt_get_data(pkt, opaque), renamed_iip_ops_pkt_get_data(m, opaque), renamed_iip_ops_pkt_get_len(m, opaque), 1);
		__MPK_iip_ops_pkt_set_len(pkt, renamed_iip_ops_pkt_get_len(m, opaque), opaque);
		ret = __MPK_iip_ops_tcp_accepted(mem, handle, pkt, opaque);
		__MPK_iip_ops_pkt_free(pkt, opaque);
	}
	return ret;
}

static void *renamed_iip_ops_tcp_connected(void *mem, void *handle, void *m, void *opaque)
{
	void *ret;
	{
		void *pkt = __MPK_iip_ops_pkt_alloc(opaque);
		__iip_assert(pkt);
		iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, __MPK_iip_ops_pkt_get_data(pkt, opaque), renamed_iip_ops_pkt_get_data(m, opaque), renamed_iip_ops_pkt_get_len(m, opaque), 1);
		__MPK_iip_ops_pkt_set_len(pkt, renamed_iip_ops_pkt_get_len(m, opaque), opaque);
		ret = __MPK_iip_ops_tcp_connected(mem, handle, pkt, opaque);
		__MPK_iip_ops_pkt_free(pkt, opaque);
	}
	return ret;
}

static void renamed_iip_ops_tcp_payload(void *mem, void *handle, void *m, void *tcp_opaque, uint16_t head_off, uint16_t tail_off, void *opaque)
{
	if (__EXPERIMENT_NO_BATCHING) {
		void *rx_pkt = ((struct mpkt *) m)->rx_pkt;
		((struct mpkt *) m)->rx_pkt = NULL; /* avoid getting released in renamed_iip_ops_pkt_free */
		__MPK_iip_ops_tcp_payload(mem, handle, rx_pkt, tcp_opaque, head_off, tail_off, opaque);
		renamed_iip_tcp_rxbuf_consumed(mem, handle, 1, opaque);
	} else {
		struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
		__iip_assert(mm->tcp_payload_queue.cnt < NUM_MPKT);
		mm->tcp_payload_queue.args[mm->tcp_payload_queue.cnt].mem = mem;
		mm->tcp_payload_queue.args[mm->tcp_payload_queue.cnt].handle = handle;
		mm->tcp_payload_queue.args[mm->tcp_payload_queue.cnt].pkt = ((struct mpkt *) m)->rx_pkt;
		mm->tcp_payload_queue.args[mm->tcp_payload_queue.cnt].tcp_opaque = tcp_opaque;
		mm->tcp_payload_queue.args[mm->tcp_payload_queue.cnt].head_off = head_off;
		mm->tcp_payload_queue.args[mm->tcp_payload_queue.cnt].tail_off = tail_off;
		mm->tcp_payload_queue.args[mm->tcp_payload_queue.cnt].opaque = opaque;
		mm->tcp_payload_queue.cnt++;
		((struct mpkt *) m)->rx_pkt = NULL; /* avoid getting released in renamed_iip_ops_pkt_free */
		if (__iip_ntohl(((struct iip_tcp_conn *) handle)->ack_seq_be) - ((struct iip_tcp_conn *) handle)->ack_seq_sent > 1000 /* threshold */)
			renamed_iip_tcp_send(mem, handle, NULL, 0, opaque);
	}
}

static void renamed_iip_ops_tcp_acked(void *mem, void *handle, void *m, void *tcp_opaque, void *opaque)
{
	if (__EXPERIMENT_NO_BATCHING)
		__MPK_iip_ops_tcp_acked(mem, handle, ((struct mpkt *) m)->tx_pkt, tcp_opaque, opaque);
	else {
		struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
		__iip_assert(mm->tcp_acked_queue.cnt < NUM_MPKT);
		mm->tcp_acked_queue.args[mm->tcp_acked_queue.cnt].mem = mem;
		mm->tcp_acked_queue.args[mm->tcp_acked_queue.cnt].handle = handle;
		mm->tcp_acked_queue.args[mm->tcp_acked_queue.cnt].pkt = ((struct mpkt *) m)->tx_pkt;
		mm->tcp_acked_queue.args[mm->tcp_acked_queue.cnt].tcp_opaque = tcp_opaque;
		mm->tcp_acked_queue.args[mm->tcp_acked_queue.cnt].opaque = opaque;
		mm->tcp_acked_queue.args[mm->tcp_acked_queue.cnt].pkt = ((struct mpkt *) m)->tx_pkt;
		mm->tcp_acked_queue.cnt++;
	}
}

static void __BATCHED_tcp_input(void *opaque)
{
	if (!__EXPERIMENT_NO_BATCHING) {
		struct mpkt_meta *mm = _MPKMETA(((struct mpk_opaque *) opaque)->workspace);
		if (mm->tcp_payload_queue.cnt || mm->tcp_acked_queue.cnt) {
			long rsp = (long)((unsigned long)(((struct mpk_opaque *) opaque)->orig_stack - (mm->tcp_payload_queue.cnt + mm->tcp_acked_queue.cnt + 1) * 64) & 0xffffffffffffffc0);
			long _arg[256] __attribute__((aligned(64))) = { 0 }, *arg = _arg, copied = 0;
			{
				_arg[1] = (long) ((struct mpk_opaque *) opaque)->workspace;
				_arg[2] = rsp + 64;
				_arg[3] = mm->tcp_payload_queue.cnt;
				_arg[4] = rsp + (mm->tcp_payload_queue.cnt + 1) * 64;
				_arg[5] = mm->tcp_acked_queue.cnt;
				_arg[6] = (long) ((struct mpk_opaque *) opaque)->opaque;
				arg = &_arg[8];
			}
			{
				uint32_t i;
				for (i = 0; i < mm->tcp_payload_queue.cnt; i++) {
					arg[0] = (long) mm->tcp_payload_queue.args[i].mem;
					arg[1] = mm->tcp_payload_queue.args[i].head_off;
					arg[2] = mm->tcp_payload_queue.args[i].tail_off;
					arg[3] = (long) mm->tcp_payload_queue.args[i].handle;
					arg[4] = (long) mm->tcp_payload_queue.args[i].tcp_opaque;
					arg[5] = (long) ((struct mpk_opaque *) opaque)->opaque;
					arg[6] = (long) mm->tcp_payload_queue.args[i].pkt;
					arg = &arg[8];
					if (arg == &_arg[256]) {
						iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp + copied, (void *) _arg, sizeof(_arg), 1);
						copied += sizeof(_arg);
						arg = _arg;
					}
				}
			}
			{
				uint32_t i;
				for (i = 0; i < mm->tcp_acked_queue.cnt; i++) {
					arg[0] = (long) mm->tcp_acked_queue.args[i].mem;
					arg[3] = (long) mm->tcp_acked_queue.args[i].handle;
					arg[4] = (long) mm->tcp_acked_queue.args[i].tcp_opaque;
					arg[5] = (long) ((struct mpk_opaque *) opaque)->opaque;
					arg[6] = (long) mm->tcp_acked_queue.args[i].pkt;
					arg = &arg[8];
					if (arg == &_arg[256]) {
						iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp + copied, (void *) _arg, sizeof(_arg), 1);
						copied += sizeof(_arg);
						arg = _arg;
					}
				}
			}
			if (arg != _arg)
				iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, (void *) rsp + copied, (void *) _arg, (uintptr_t) arg - (uintptr_t) _arg, 1);
			mpk_call(((struct mpk_opaque *) opaque)->orig_pkru, rsp, 0, 0, 0, MPK_IIP_OPS_BATCHED_tcp_input);
			{
				uint32_t i;
				for (i = 0; i < mm->tcp_payload_queue.cnt; i++)
					renamed_iip_tcp_rxbuf_consumed(mm->tcp_payload_queue.args[i].mem, mm->tcp_payload_queue.args[i].handle, 1, opaque);
			}
			mm->tcp_payload_queue.cnt = 0;
			mm->tcp_acked_queue.cnt = 0;
		}
	}
}

static void renamed_iip_ops_tcp_closed(void *handle, uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be, uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be, void *tcp_opaque, void *opaque)
{
	__BATCHED_tcp_input(opaque);
	__MPK_iip_ops_tcp_closed(handle, local_mac, local_ip4_be, local_port_be, peer_mac, peer_ip4_be, peer_port_be, tcp_opaque, opaque);
}

static void renamed_iip_ops_udp_payload(void *mem, void *m, void *opaque)
{
	void *pkt = __MPK_iip_ops_pkt_alloc(opaque);
	__iip_assert(pkt);
	iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, __MPK_iip_ops_pkt_get_data(pkt, opaque), renamed_iip_ops_pkt_get_data(m, opaque), renamed_iip_ops_pkt_get_len(m, opaque), 1);
	__MPK_iip_ops_pkt_set_len(pkt, renamed_iip_ops_pkt_get_len(m, opaque), opaque);
	__MPK_iip_ops_udp_payload(mem, pkt, opaque);
	__MPK_iip_ops_pkt_free(pkt, opaque);
}

#if __EXPERIMENT_NO_PKRU
#define PKRU_ASSERT
#else
#define PKRU_ASSERT __iip_assert(orig_pkru == 0x55555550)
#endif

long MPK_IIP_add_pb(long orig_pkru __attribute__((unused)), long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	renamed_iip_add_pb((void *) a1 /* _mem */, (void *) a2 /* _p */);
	return 0;
}

long MPK_IIP_add_tcp_conn(long orig_pkru __attribute__((unused)), long orig_stack __attribute__((unused)),
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2)
{
	PKRU_ASSERT; /* debug */
	renamed_iip_add_tcp_conn((void *) a1 /* _mem */, (void *) a2 /* _conn */);
	return 0;
}

long MPK_IIP_arp_request(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4, long a5)
{
	struct mpk_opaque _opaque = {
		.orig_pkru = orig_pkru,
		.orig_stack = orig_stack & 0xffffffffffffffc0,
		.workspace = (void *) a1,
		.opaque = (void *) a5,
	}, *opaque = &_opaque;
	PKRU_ASSERT; /* debug */
	renamed_iip_arp_request((void *) a1 /* _mem */, (void *) a2 /* local_mac */, a3 /* local_ip4_be */, a4 /* target_ip4_be */, opaque);
	return 0;
}

long MPK_IIP_tcp_close(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3)
{
	struct mpk_opaque _opaque = {
		.orig_pkru = orig_pkru,
		.orig_stack = orig_stack & 0xffffffffffffffc0,
		.workspace = (void *) a1,
		.opaque = (void *) a3,
	}, *opaque = &_opaque;
	PKRU_ASSERT; /* debug */
	return renamed_iip_tcp_close((void *) a1 /* _mem */, (void *) a2 /* _handle */, opaque);
}

long MPK_IIP_tcp_rxbuf_consumed(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
					 long a0 __attribute__((unused)), long a1, long a2, long a3, long a4)
{
	struct mpk_opaque _opaque = {
		.orig_pkru = orig_pkru,
		.orig_stack = orig_stack & 0xffffffffffffffc0,
		.workspace = (void *) a1,
		.opaque = (void *) a4,
	}, *opaque = &_opaque;
	PKRU_ASSERT; /* debug */
	renamed_iip_tcp_rxbuf_consumed((void *) a1 /* _mem */, (void *) a2 /* _handle */, a3 /* cnt */, opaque);
	return 0;
}

long MPK_IIP_tcp_connect(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	struct mpk_opaque _opaque = {
		.orig_pkru = orig_pkru,
		.orig_stack = orig_stack & 0xffffffffffffffc0,
		.workspace = (void *) a1,
		.opaque = (void *) a8,
	}, *opaque = &_opaque;
	PKRU_ASSERT; /* debug */
	return renamed_iip_tcp_connect((void *) a1 /* _mem */, (void *) a2 /* local_mac */, a3 /* local_ip4_be */, a4 /* local_port_be */, (void *) a5 /* peer_mac */, a6 /* peer_ip4_be */, a7 /* peer_port_be */, opaque);
}

long MPK_IIP_tcp_send(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3 __attribute__((unused)), long a4, long a5, long a6, long a7)
{
	struct mpk_opaque _opaque = {
		.orig_pkru = orig_pkru,
		.orig_stack = orig_stack & 0xffffffffffffffc0,
		.workspace = (void *) a1,
		.opaque = (void *) a5,
	}, *opaque = &_opaque;
	PKRU_ASSERT; /* debug */
	{
		struct mpkt *mpkt;
		if (a7 <= IIP_CONF_TCP_OPT_MSS)
			mpkt = renamed_iip_ops_pkt_alloc(opaque);
		else
			mpkt = __iip_ops_pkt_alloc_large(opaque);
		__iip_assert(mpkt);
		mpkt->tx_pkt = (void *) a3;
		renamed_iip_ops_pkt_set_len(mpkt, a7, opaque);
		if (__EXPERIMENT_NO_MEMCOPYSKIP
				|| !(renamed_iip_ops_nic_feature_offload_tx_scatter_gather(opaque)
					&& renamed_iip_ops_nic_feature_offload_ip4_tx_checksum(opaque)
					&& renamed_iip_ops_nic_feature_offload_tcp_tx_checksum(opaque)))
			iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, mpkt->data, (uint8_t *) a6, a7, 0);
		return renamed_iip_tcp_send((void *) a1, (void *) a2, (void *) mpkt, a4, opaque);
	}
}

long MPK_IIP_udp_send(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8, long a9)
{
	struct mpk_opaque _opaque = {
		.orig_pkru = orig_pkru,
		.orig_stack = orig_stack & 0xffffffffffffffc0,
		.workspace = (void *) a1,
		.opaque = (void *) a9,
	}, *opaque = &_opaque;
	PKRU_ASSERT; /* debug */
	{
		long ret;
		{
			struct mpkt *mpkt = renamed_iip_ops_pkt_alloc(opaque);
			__iip_assert(mpkt);
			renamed_iip_ops_pkt_set_len(mpkt, __MPK_iip_ops_pkt_get_len((void *) a8, opaque), opaque);
			iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, mpkt->data, (uint8_t *) __MPK_iip_ops_pkt_get_data((void *) a8, opaque), mpkt->len, 0);
			ret = renamed_iip_udp_send((void *) a1 /* _mem */, (void *) a2 /* local_mac */, a3 /* local_ip4_be */, a4 /* local_port_be */, (void *) a5 /* peer_mac */, a6 /* peer_ip4_be */, a7 /* peer_port_be */, (void *) mpkt, opaque);
			__MPK_iip_ops_pkt_free((void *) a8, opaque);
		}
		return ret;
	}
}

#define __PKTBUF_LARGE_THRESHOLD (1514)

long MPK_IIP_run(long orig_pkru, long orig_stack,
		long _u0 __attribute__((unused)), long _u1 __attribute__((unused)), long _u2 __attribute__((unused)), long _u3 __attribute__((unused)),
		long a0 __attribute__((unused)), long a1, long a2, long a3, long a4, long a5, long a6 __attribute__((unused)), long a7)
{
	struct mpk_opaque _opaque = {
		.orig_pkru = orig_pkru,
		.orig_stack = orig_stack & 0xffffffffffffffc0,
		.workspace = (void *) a1,
		.opaque = (void *) a7,
	}, *opaque = &_opaque;
	PKRU_ASSERT; /* debug */
	{ /* time */
		opaque->now[0] = ((a0 / 1000000000) >> 32) & 0xffffffff;
		opaque->now[1] = ((a0 / 1000000000) >>  0) & 0xffffffff;
		opaque->now[2] = (a0 % 1000000000);
	}
	{
		uint32_t next_us = 1000000U;
		{
			long c = 0;
			do {
				struct mpkt *mpkt[64];
				{
					uint16_t i;
					for (i = 0; i < (sizeof(mpkt) / sizeof(mpkt[0])) && c < a5 /* cnt */; i++, c++) {
						if (((long *) a4)[(c << 3) + 2] <= __PKTBUF_LARGE_THRESHOLD)
							mpkt[i] = renamed_iip_ops_pkt_alloc(opaque);
						else
							mpkt[i] = __iip_ops_pkt_alloc_large(opaque);
						__iip_assert(mpkt[i]);
						mpkt[i]->rx_flags = ((long *) a4)[(c << 3) + 4];
						mpkt[i]->rx_pkt = (void *) ((long *) a4)[(c << 3) + 3];
						renamed_iip_ops_pkt_set_len(mpkt[i], ((long *) a4)[(c << 3) + 2], opaque);
						if (!__EXPERIMENT_NO_MEMCOPYSKIP
								&& (((long *) a4)[(c << 3) + 2] > __PKTBUF_LARGE_THRESHOLD
									&& renamed_iip_ops_nic_feature_offload_ip4_rx_checksum(opaque)
									&& renamed_iip_ops_nic_feature_offload_tcp_rx_checksum(opaque)
									&& renamed_iip_ops_nic_offload_ip4_rx_checksum(mpkt[i], opaque)
									&& renamed_iip_ops_nic_offload_tcp_rx_checksum(mpkt[i], opaque))) {
							iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, renamed_iip_ops_pkt_get_data(mpkt[i], (void *) opaque), (uint8_t *) ((long *) a4)[(c << 3) + 1], __PKTBUF_LARGE_THRESHOLD, 0);
							continue;
						}
						iip_mpk_memory_copy_64b(((struct mpk_opaque *) opaque)->orig_pkru, renamed_iip_ops_pkt_get_data(mpkt[i], (void *) opaque), (uint8_t *) ((long *) a4)[(c << 3) + 1], mpkt[i]->len, 0);
					}
				}
				renamed_iip_run((void *) a1 /* _mem */, (void *) a2 /* mac */, a3 /* ip4_be */, (void **) mpkt, a5 /* cnt */, &next_us, opaque);
			} while (c < a5 /* cnt */);
		}
		__BATCHED_tcp_input(opaque);
		return next_us;
	}
	{ /* unused */
		(void) __MPK_iip_ops_tcp_acked;
		(void) __MPK_iip_ops_tcp_payload;
		(void) __MPK_iip_ops_nic_offload_udp_tx_tso_mark;
		(void) __MPK_iip_ops_nic_offload_udp_tx_checksum_mark;
		(void) __MPK_iip_ops_nic_offload_tcp_tx_tso_mark;
		(void) __MPK_iip_ops_nic_offload_tcp_tx_checksum_mark;
		(void) __MPK_iip_ops_nic_offload_ip4_tx_checksum_mark;
		(void) __MPK_iip_ops_nic_offload_udp_rx_checksum;
		(void) __MPK_iip_ops_nic_offload_tcp_rx_checksum;
		(void) __MPK_iip_ops_nic_offload_ip4_rx_checksum;
		(void) __MPK_iip_ops_l2_push;
		(void) __MPK_iip_ops_l2_flush;
		(void) __MPK_iip_ops_l2_skip;
		(void) __MPK_iip_ops_l2_hdr_craft;
		(void) __MPK_iip_ops_l2_broadcast_addr;
		(void) __MPK_iip_ops_l2_ethertype_be;
		(void) __MPK_iip_ops_l2_hdr_dst_ptr;
		(void) __MPK_iip_ops_l2_hdr_src_ptr;
		(void) __MPK_iip_ops_l2_hdr_len;
		(void) __MPK_iip_ops_pkt_scatter_gather_chain_get_next;
		(void) __MPK_iip_ops_pkt_scatter_gather_chain_append;
		(void) __MPK_iip_ops_pkt_clone;
		(void) __MPK_iip_ops_pkt_decrement_tail;
		(void) __MPK_iip_ops_pkt_increment_head;
		(void) __MPK_iip_ops_util_now_ns;
	}
}

long MPK_IIP_BATCHED_tcp_send(long orig_pkru, long orig_stack, long a0, long a1, long a2)
{
	struct mpk_opaque _opaque = {
		.orig_pkru = orig_pkru,
		.orig_stack = orig_stack & 0xffffffffffffffc0,
		.workspace = (void *) a0,
	}, *opaque = &_opaque;
	PKRU_ASSERT; /* debug */
	{
		long *arg = (long *) a1;
		{
			uint32_t i;
			for (i = 0; i < (uint32_t) a2; i++) {
				struct mpkt *mpkt;
				if (arg[2] <= IIP_CONF_TCP_OPT_MSS)
					mpkt = renamed_iip_ops_pkt_alloc(opaque);
				else
					mpkt = __iip_ops_pkt_alloc_large(opaque);
				if (__EXPERIMENT_NO_MEMCOPYSKIP
						|| !(renamed_iip_ops_nic_feature_offload_tx_scatter_gather(opaque)
							&& renamed_iip_ops_nic_feature_offload_ip4_tx_checksum(opaque)
							&& renamed_iip_ops_nic_feature_offload_tcp_tx_checksum(opaque)))
					iip_mpk_memory_copy_64b(orig_pkru, renamed_iip_ops_pkt_get_data((void *) mpkt, opaque), (void *) arg[1], arg[2], 0);
				renamed_iip_ops_pkt_set_len((void *) mpkt, arg[2], opaque);
				mpkt->tx_pkt = (void *) arg[6];
				renamed_iip_tcp_send((void *) arg[0], (void *) arg[3], (void *) mpkt, arg[4], opaque);
				arg = &arg[8];
			}
		}
	}
	return 0;
}

char __debug_experiment_no_pkru(void)
{
	return __EXPERIMENT_NO_PKRU;
}

char __debug_experiment_no_batching(void)
{
	return __EXPERIMENT_NO_BATCHING;
}

char __debug_experiment_no_memcopyskip(void)
{
	return __EXPERIMENT_NO_MEMCOPYSKIP;
}

uint32_t exposed_iip_workspace_size(void)
{
	return renamed_iip_workspace_size();
}

uint32_t exposed_iip_pb_size(void)
{
	return renamed_iip_pb_size();
}

uint32_t exposed_iip_tcp_conn_size(void)
{
	return renamed_iip_tcp_conn_size();
}

