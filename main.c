#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_arp.h>
#include <rte_ether.h>

#define MAX_PCKT_BURST_DEFAULT 64
#define MEMPOOL_CACHE_SIZE     256
#define RTE_RX_DESC_DEFAULT    4096
#define RTE_TX_DESC_DEFAULT    4096
#define MAX_RX_PORTS_PER_LCORE 1
#define MAX_TX_PORTS_PER_LCORE 1
#define MAX_RX_QUEUES_PER_PORT 32
#define MAX_TX_QUEUES_PER_PORT 32
#define RSS_HASH_KEY_LENGTH    40

volatile __u8  quit          = 0;
volatile __u64 pckts_counter = 0;

__u16 nb_rxd = RTE_RX_DESC_DEFAULT;
__u16 nb_txd = RTE_TX_DESC_DEFAULT;

static uint8_t rss_hash_key[RSS_HASH_KEY_LENGTH] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

struct rte_eth_conf port_conf = {
    .rxmode =
    {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
    },

    .rx_adv_conf = {
        .rss_conf = {
            .rss_key     = rss_hash_key,
            .rss_key_len = RSS_HASH_KEY_LENGTH,
            .rss_hf      = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },

    .txmode =
    {
        .mq_mode = RTE_ETH_MQ_TX_NONE
    }
};

typedef struct lcore_params_t 
{
    unsigned port_id;
    unsigned queue_id;
} lcore_params_t;

static int rx_lcore(lcore_params_t *p)
{
    unsigned lc_id = rte_lcore_id();
    struct rte_mbuf *pckts_burst[MAX_PCKT_BURST_DEFAULT];
    unsigned i;
    unsigned nb_rx;
    
    printf("[%d][%d] rx_lcore\n", lc_id, p->queue_id);
    
    while (!quit)
    {
        nb_rx = rte_eth_rx_burst(p->port_id, p->queue_id, pckts_burst, MAX_PCKT_BURST_DEFAULT);

        if (unlikely(nb_rx == 0)) {
            continue;
        } 
        
        pckts_counter += nb_rx;

        for (i = 0; i < nb_rx; i++)
        {
            rte_pktmbuf_free(pckts_burst[i]);            
        }
    }

    printf("Core %d exiting\n", lc_id);

    return 1;
}

static void sign_hdl(int tmp)
{
    quit = 1;
}

int main(int argc, char **argv)
{
    lcore_params_t *params[RTE_MAX_LCORE];
    unsigned i;
    unsigned lc_id;
    unsigned port_id;
    unsigned rx_queues;
    unsigned tx_queues;
    struct rte_mempool *pcktmbuf_pool;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_link link;
    char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];
    __u64 last_count = 0;
    
    if ( rte_eal_init(argc, argv) < 0 )
        rte_exit(EXIT_FAILURE, "Failed to initialize EAL\n");
    
    quit = 0;
    signal(SIGINT,  sign_hdl);
    signal(SIGTERM, sign_hdl);
    
    port_id   = 0;
    rx_queues = 8;
    tx_queues = 8;
    
    pcktmbuf_pool = rte_pktmbuf_pool_create("rx_pool", 524288U, MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if ( pcktmbuf_pool == NULL )
        rte_exit(EXIT_FAILURE, "Failed to create packet's mbuf pool\n");
    
    if ( rte_eth_dev_info_get(port_id, &dev_info) != 0 )
        rte_exit(EXIT_FAILURE, "Failed to retrieve device info\n");
        
    if ( dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM ) {
        port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_CHECKSUM;
    }  
    
    if ( rte_eth_dev_configure(port_id, rx_queues, tx_queues, &port_conf) < 0 )
        rte_exit(EXIT_FAILURE, "Failed to configure ethernet device with RX and TX queues\n");
    
    if ( rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd) < 0 )
        rte_exit(EXIT_FAILURE, "Failed to configure ethernet device with RX and TX adjust\n");
        
    for (i = 0; i < rx_queues; i++)
    {
        struct rte_eth_rxconf rxq_conf;

        rxq_conf          = dev_info.default_rxconf;
        rxq_conf.offloads = port_conf.rxmode.offloads;

        if ( rte_eth_rx_queue_setup(port_id, i, nb_rxd, rte_eth_dev_socket_id(port_id), &rxq_conf, pcktmbuf_pool) < 0 )
            rte_exit(EXIT_FAILURE, "Failed to setup RX queue %d\n", i);
    }
    
    for (i = 0; i < tx_queues; i++)
    {
        struct rte_eth_txconf txq_conf;

        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = port_conf.txmode.offloads;
        
        if ( rte_eth_tx_queue_setup(port_id, i, nb_txd, rte_eth_dev_socket_id(port_id), &txq_conf) < 0 )
            rte_exit(EXIT_FAILURE, "Failed to setup TX queue %d\n", i);
    }
    
    if ( rte_eth_dev_set_ptypes(port_id, RTE_PTYPE_UNKNOWN, NULL, 0) < 0 )
        rte_exit(EXIT_FAILURE, "Failed to disable PType parsing for performance\n");
    
    if ( rte_eth_dev_start(port_id) < 0 )
        rte_exit(EXIT_FAILURE, "Failed to start device\n");
    
    if ( rte_eth_promiscuous_enable(port_id) < 0 )
        rte_exit(EXIT_FAILURE, "Failed to enable promiscuous mode on port\n");
        
    fprintf(stdout, "Port #%d setup successfully with %d RX queues and %d TX queues\n", port_id, rx_queues, tx_queues);
    
    for(i = 0; i < 3; i++)
    {
        memset(&link, 0, sizeof(link));
        
        int ret = rte_eth_link_get_nowait(port_id, &link);
        if (ret < 0) {
            fprintf(stderr, "Port %u link failed: %s.\n", port_id, rte_strerror(-ret));
            continue;
        }
        
        rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
        fprintf(stdout, "Port %d => %s.\n", port_id, link_status_text);
        
        if (link.link_status == RTE_ETH_LINK_DOWN || link.link_status == RTE_ETH_LINK_UP)
            break;
    }
    
    if (link.link_status == RTE_ETH_LINK_DOWN)
        rte_exit(EXIT_FAILURE, "Link down\n");
    
    lc_id = 1;
    
    // Start rx cores
    for (i = 0; i < rx_queues; i++)
    {
        params[lc_id] = rte_zmalloc(NULL, sizeof(lcore_params_t), 0);
        if (!params[lc_id])
            rte_panic("malloc failure\n");

        params[lc_id]->port_id  = port_id;
        params[lc_id]->queue_id = i;

        int res = rte_eal_remote_launch((lcore_function_t *)rx_lcore, (void*)params[lc_id], lc_id);
        if (res != 0)
            rte_exit(EXIT_FAILURE, "Cannot start rx_lcore %d\n", lc_id);

        lc_id++;
    }
    
    fprintf(stdout, "Started %d rx_cores\n", i);
    
    while (!quit)
    {
        fprintf(stdout, "pps: %llu\n", (pckts_counter - last_count) / 3);
        last_count = pckts_counter;
        
        sleep(3);        
    }
    
    // End
    
    RTE_LCORE_FOREACH_WORKER(lc_id)
    {
        if (rte_eal_wait_lcore(lc_id) < 0)
            break;
    }
    
    RTE_ETH_FOREACH_DEV(port_id)
    {
        fprintf(stdout, "Closing port #%u.\n", port_id);

        if ( rte_eth_dev_stop(port_id) != 0 )
            return 0;

        rte_eth_dev_close(port_id);
    }
    
    rte_eal_cleanup();
    
    return 0;
}

