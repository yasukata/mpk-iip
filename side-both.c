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

#ifndef __EXPERIMENT_NO_PKRU
#define __EXPERIMENT_NO_PKRU (0)
#endif
#ifndef __EXPERIMENT_NO_BATCHING
#define __EXPERIMENT_NO_BATCHING (0)
#endif
#ifndef __EXPERIMENT_NO_MEMCOPYSKIP
#define __EXPERIMENT_NO_MEMCOPYSKIP (0)
#endif

#define _STACK_SIZE (1U << 23)
#define _MISC_BUF_SIZE (1U << 23)

#define MPKTBUF_LEN (2048)
#define NUM_MPKT_BUF (512)
#define MPKTBUF_LARGE_LEN (0x10000)
#define NUM_MPKT_BUF_LARGE (512)
#define NUM_MPKT (512)

#define __MPK_IIP_WORKSPACE_SIZE (1U << 21)

#define _MPKMETA(__mem) ((struct mpkt_meta *)((uintptr_t) (__mem) + __MPK_IIP_WORKSPACE_SIZE))
#define _MPKMISC(__mem) ((uintptr_t) _MPKMETA(__mem) + ((((sizeof(struct mpkt_meta)) >> 12) + 1) << 12))
#define _MPKBUF_START(__mem) ((uintptr_t) _MPKMISC(__mem) + _MISC_BUF_SIZE)
#define MPKTBUF(__mem, __i) ((void *)(_MPKBUF_START(__mem) + MPKTBUF_LEN * (__i)))
#define MPKTBUF_LARGE(__mem, __i) ((void *)((uintptr_t) MPKTBUF(__mem, NUM_MPKT_BUF) + MPKTBUF_LARGE_LEN * (__i)))
#define MPKT(__mem, __i) ((struct mpkt *) ((uintptr_t) MPKTBUF_LARGE(__mem, NUM_MPKT_BUF_LARGE) + sizeof(struct mpkt) * (__i)))

struct mpkt {
	uint16_t len;
	uint16_t head;
	uint32_t rx_flags;
	uint32_t tx_flags;
	uint8_t *data;
	void *tx_pkt;
	void *rx_pkt;
	struct mpkt *next;
};

struct mpkt_meta {
	uint32_t magic;
	struct {
		uint8_t bcaddr[64];
		uint8_t bcaddr_set;
		uint16_t l2_addr_len;
		uint16_t l2_hdr_len;
		uint8_t offload_tx_scatter_gather;
		uint8_t offload_ip4_rx_checksum;
		uint8_t offload_ip4_tx_checksum;
		uint8_t offload_tcp_rx_checksum;
		uint8_t offload_tcp_tx_checksum;
		uint8_t offload_tcp_tx_tso;
		uint8_t offload_udp_rx_checksum;
		uint8_t offload_udp_tx_checksum;
		uint8_t offload_udp_tx_tso;
	} nic_feature;
	struct {
		uint32_t cnt;
		void *p[NUM_MPKT_BUF];
		uint32_t ref[NUM_MPKT_BUF];
	} mpktbuf_queue;
	struct {
		uint32_t cnt;
		void *p[NUM_MPKT_BUF_LARGE];
		uint32_t ref[NUM_MPKT_BUF_LARGE];
	} mpktbuf_large_queue;
	struct {
		uint32_t cnt;
		struct mpkt *p[NUM_MPKT];
	} mpkt_queue;
	struct {
		uint32_t cnt;
		uint32_t total;
		struct mpkt *p[NUM_MPKT];
	} tx_queue;
	struct {
		uint32_t cnt;
		struct {
			void *mem;
			void *handle;
			void *pkt;
			void *tcp_opaque;
			uint16_t head_off;
			uint16_t tail_off;
			void *opaque;
		} args[NUM_MPKT];
	} tcp_payload_queue;
	struct {
		uint32_t cnt;
		struct {
			void *mem;
			void *handle;
			void *pkt;
			void *tcp_opaque;
			void *opaque;
		} args[NUM_MPKT];
	} tcp_acked_queue;
};

extern long mpk_call(int, ...);
extern long zmm_memcpy_64b(int, uint8_t *, const uint8_t *, uint32_t, char);

