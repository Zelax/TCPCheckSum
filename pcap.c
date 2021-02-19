#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>

#include "pcap.h"

typedef struct pcap_hdr {
  uint32_t magic_number;   /**< magic number */
  uint16_t version_major;  /**< major version number */
  uint16_t version_minor;  /**< minor version number */
  int32_t  thiszone;       /**< Разница в секундах между часовым поясом GMT
                                и часовым поясом меток времени в pcap-файле.
                                На практике всегда 0. */
  uint32_t sigfigs;        /**< Точность меток времени. На практике всегда 0. */
  uint32_t snaplen;        /**< Максимальная длина перехваченных пакетов в
                                октетах */
  uint32_t network;        /**< Тип канала передачи данных */
} __attribute__((packed)) pcap_hdr_t;

enum read_ret_code {
  RRC_EOF,
  RRC_FAIL,
  RRC_SUCCESS
};

static enum read_ret_code read_rec(int f, pcap_rec_t **out) {

  pcap_rec_t *prec = (pcap_rec_t*)malloc(sizeof(pcap_rec_t));
  int bytes = read(f, &prec->rec, sizeof(struct pcaprec_hdr));
  if (bytes == -1) {
    fprintf( stderr, "Read pcap record header error: %d", errno);
    free(prec);
    return RRC_FAIL;
  }
  if (!bytes) {
    free(prec);
    return RRC_EOF;
  }

  if (prec->rec.incl_len != prec->rec.orig_len) {
    fprintf( stderr, "Pcap record included length not equal to origin "
          "length of packet");
    free(prec);
    return RRC_FAIL;
  }

  prec->data = (uint8_t*) malloc(prec->rec.incl_len);
  bytes = read(f, prec->data, prec->rec.incl_len);
  if (bytes == -1 || !bytes) {
    fprintf( stderr, "Read pcap record body error: %d", errno);
    free(prec->data);
    free(prec);
    return RRC_FAIL;
  }

  *out = prec;
  return RRC_SUCCESS;
}

int pcap_load(const char *file, list_head_t *head) {
  int f = open(file, O_RDONLY);
  if (!f) {
    fprintf( stderr, "Can't open file %s", file);
    return 0;
  }

  pcap_hdr_t hdr;
  int bytes = read(f, &hdr, sizeof(pcap_hdr_t));
  if (bytes == -1) {
    fprintf( stderr, "Read pcap header error: %d", errno);
    close(f);
    return 0;
  }
  if (hdr.magic_number != 0xa1b2c3d4) {
    fprintf( stderr, "This byte ordering in pcap file not supported");
    close(f);
    return 0;
  }

  pcap_rec_t *rec;
  enum read_ret_code rrc = read_rec(f, &rec);
  while (rrc == RRC_SUCCESS) {
    list_add(head, &rec->list);
    rrc = read_rec(f, &rec);
  }

  close(f);

  if (rrc == RRC_FAIL) {
    pcap_free(head);
    return 0;
  }

  return 1;
}

void pcap_free(list_head_t *head) {
  list_head_t *it = head->next;
  while (it != head) {
    pcap_rec_t *rec = LIST_GET_ENTRY(it, pcap_rec_t, list);
    it = it->next;

    list_del(&rec->list);
    free(rec->data);
    free(rec);
  }
}
