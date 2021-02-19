#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "pcap.h"
#include "list.h"
#include "checksum.h"

typedef struct tcp_pseudo {
  __be32 saddr;
  __be32 daddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t len;
} __attribute__((packed)) tcp_pseudo_t;

typedef struct tcp_list_entry {
  list_head_t list;
  tcp_pseudo_t pseudo;
  uint16_t tcp_len;
  void *tcp;
} tcp_list_entry_t;

const char *pcap_file = NULL;
enum checksum_algorithm selected_alg = CSA_C;
unsigned long iterations = 50;

void print_usage() {
  printf("Usage: ip-checksum-test [OPTION] PCAP_FILE\n");
  printf("Evaluate IP checksum functions performance.\n");
  printf("Test data set in pcap format. It must contain TCP traffic.\n");
  printf("OPTIONS:\n");
  printf("    -a <alg>  specify algorithm to use. Default is 'ref'. Possible values are:\n");
  printf("              ref - reference algorithm, author Diego Pino García\n");
#ifdef ALG_AMD64
  printf("              amd64 - optimized algorithm for\n");
  printf("                      amd64 architecture, author Diego Pino García\n");
#endif
  printf("    -n <num>  specify number of iterations over PCAP_FILE. Default value is 50.\n");
}

unsigned long parse_num(char *str) {
  char *endptr;
  errno = 0;
  unsigned long val = strtoul(str, &endptr, 0);

  if (errno != 0 || endptr == str || *endptr != '\0') {
    fprintf(stderr, "Can't parse number '%s'.\n", str);
    exit(EXIT_FAILURE);
  }

  return val;
}

void cli_parse_args(int argc, char **argv) {
  int c;
  const char *alg_name = "c";

  while ((c = getopt(argc, argv, "a:n:h")) != -1) {
    switch (c) {
      case 'a':
        alg_name = optarg;
#ifdef ALG_AMD64
        if (!strcmp(alg_name, "amd64")) {
          selected_alg = CSA_AMD64;
        } else
#endif
        if (strcmp(alg_name, "ref")) {
          fprintf(stderr, "Invalid algorithm argument %s.\n", alg_name);
          exit(EXIT_FAILURE);
        }
        break;
      case 'n':
        iterations = parse_num(optarg);
        break;
      case 'h':
        print_usage();
        exit(EXIT_SUCCESS);
        break;
      case '?':
        exit(EXIT_FAILURE);
    }
  }

  if (argc - optind != 1) {
    fprintf(stderr, "Specify one pcap file to read.\n");
    exit(EXIT_FAILURE);
  }

  pcap_file = argv[optind];
}

static double diff_timespec(const struct timespec *t1, const struct timespec *t2) {
  return (t1->tv_sec - t2->tv_sec) + (double)(t1->tv_nsec - t2->tv_nsec)/1000000000;
}

static void tcp_list_init(list_head_t *tcp_list, list_head_t *pkts_list, uint64_t *tcp_pkts,
                          uint64_t *tcp_bytes) {
  uint64_t pkts = 0;
  uint64_t bytes = 0;
  struct ether_header *eth;
  uint32_t eth_hdr_len = sizeof(struct ether_header);
  tcp_list_entry_t *p;
  list_head_t *it;

  for (it = pkts_list->prev; it != pkts_list; it = it->prev) {
    pcap_rec_t *rec = LIST_GET_ENTRY(it, pcap_rec_t, list);

    eth = (struct ether_header*)rec->data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
      continue;
    // Фреймы с тегами 802.1q мы не поддерживаем, поэтому считаем, что сразу за
    // Eth заголовком идет IP заголовок.
    struct iphdr *ip = (struct iphdr*)(rec->data + eth_hdr_len);
    // Работаем только с TCP.
    if (ip->protocol != 6)
      continue;

    uint16_t tcp_len = ntohs(ip->tot_len) - ip->ihl*4;

    p = (tcp_list_entry_t*)malloc(sizeof(tcp_list_entry_t));
    p->pseudo.zero = 0;
    p->pseudo.protocol = 6;
    p->pseudo.saddr = ip->saddr;
    p->pseudo.daddr = ip->daddr;
    p->pseudo.len = htons(tcp_len);
    p->tcp = (uint8_t*)(rec->data + eth_hdr_len + ip->ihl*4);
    p->tcp_len = tcp_len;

    pkts++;
    bytes += tcp_len + sizeof(tcp_pseudo_t);

    list_add(tcp_list, &p->list);
  }
  *tcp_pkts = pkts;
  *tcp_bytes = bytes;
}

static void tcp_list_free(list_head_t *tcp_list) {
  list_head_t *it = tcp_list->prev;
  while (it != tcp_list) {
    tcp_list_entry_t *p = LIST_GET_ENTRY(it, tcp_list_entry_t, list);
    it = it->prev;
    free(p);
  }
}

int main(int argc, char **argv) {
  uint64_t tcp_pkts;
  uint64_t tcp_bytes;
  uint64_t tcp_sum_errs = 0;
  struct timespec st, end;
  unsigned long i;
  checksum_t cs_func;

  cli_parse_args(argc, argv);
  cs_func = checksum_funcs[selected_alg];

  list_head_t pkts_list;
  list_init(&pkts_list);
  if (!pcap_load(pcap_file, &pkts_list))
    return EXIT_FAILURE;

  list_head_t tcp_list;
  list_init(&tcp_list);
  tcp_list_init(&tcp_list, &pkts_list, &tcp_pkts, &tcp_bytes);

  clock_gettime(CLOCK_MONOTONIC_RAW, &st);

  for (i = 0; i < iterations; i++) {
    list_head_t *it;
    for (it = tcp_list.prev; it != &tcp_list; it = it->prev) {
      tcp_list_entry_t *p = LIST_GET_ENTRY(it, tcp_list_entry_t, list);

      uint16_t tcp_sum = cs_func((uint8_t*)&p->pseudo, sizeof(tcp_pseudo_t), 0);
      tcp_sum = cs_func(p->tcp, p->tcp_len, ~tcp_sum);
      if (tcp_sum)
        tcp_sum_errs++;
    }
  }

  clock_gettime(CLOCK_MONOTONIC_RAW, &end);
  double diff_s = diff_timespec(&end, &st);

  tcp_pkts *= iterations;
  tcp_bytes *= iterations;

  uint64_t pkts_per_sec = diff_s == 0 ? 0 : tcp_pkts/diff_s;
  uint64_t bytes_per_sec = diff_s == 0 ? 0 : (tcp_bytes/(1024*1024))/diff_s;

  printf("%lu TCP packets processed in %.3f s\n"
         "%lu TCP packets per second(%lu MiB/s)\n"
         "%lu TCP checksum errors\n",
         tcp_pkts, diff_s, pkts_per_sec, bytes_per_sec, tcp_sum_errs);

  tcp_list_free(&tcp_list);
  pcap_free(&pkts_list);

  return EXIT_SUCCESS;
}
