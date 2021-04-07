/*
 * Generic checksm routine taken from DPDK: 
 *   BSD license; (C) Intel 2010-2015, 6WIND 2014.
 */

#include "checksum.h"
#include <netinet/in.h>

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

uint16_t c_checksum(uint8_t *p, uint16_t len, uint16_t init)
{
  uint32_t sum = htons(init);
  const uint16_t *u16 = (const uint16_t *)p;

#ifdef __e2k__
#pragma vector aligned
#pragma unroll(4)
#endif
  while (len >= (sizeof(*u16) * 4)) {
    sum += u16[0];
    sum += u16[1];
    sum += u16[2];
    sum += u16[3];
    len -= sizeof(*u16) * 4;
    u16 += 4;
  }
  while (len >= sizeof(*u16)) {
    sum += *u16;
    len -= sizeof(*u16);
    u16 += 1;
  }

  /* if length is in odd bytes */
  if (len == 1)
    sum += *((const uint8_t *)u16);

  while(sum>>16)
    sum = (sum & 0xFFFF) + (sum>>16);
  return ntohs((uint16_t)~sum);
}
