#include "checksum.h"

uint16_t c_checksum(uint8_t *data, uint16_t len, uint16_t init);
#ifdef ALG_AMD64
uint16_t as_checksum(uint8_t *data, uint16_t len, uint16_t init);
#endif

checksum_t checksum_funcs[CSA_COUNT] = {
  c_checksum,
#ifdef ALG_AMD64
  as_checksum
#endif
};

uint16_t c_checksum(uint8_t *data, uint16_t len, uint16_t init) {
  uint64_t sum = init;
  uint16_t l = len;
  uint32_t *p = (uint32_t*) data;
  uint16_t i = 0;
  while (l >= 4) {
    sum = sum + p[i++];
    l -= 4;
  }
  if (l >= 2) {
    sum = sum + ((uint16_t*) data)[i * 2];
    l -= 2;
  }
  if (l == 1) {
    sum += data[len-1];
  }

  while (sum>>16) {
    sum = (sum & 0xffff) + (sum>>16);
  }

  return (uint16_t)~sum;
}
