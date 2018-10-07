#include "CMac.h"
#include "BlockCipher.h"
#include "XteaEngine.h"
#include <Arduino.h>

bool CMac::encrypt(int encType, uint8_t key[], int keyLength, uint8_t in[], int inLength, uint8_t out[], int outLength) {
  BlockCipher* cipher = NULL;

  switch(encType) {
    case CMac::ENCTYPE_XTEA:
    cipher = new XteaEngine(key, keyLength);
  }
  if (cipher == NULL) return false;

  int blockLength = cipher->getBlockLength();

  uint8_t *buf, *ZEROES, *Lu, *Lu2;
  buf = new uint8_t[blockLength];
  ZEROES = new uint8_t[blockLength];
  int i;
  for(i=0;i<blockLength;i++) {
    if (i<inLength) buf[i] = in[i];
    else buf[i] = 0;

    ZEROES[i] = 0;
  }
  cipher->encrypt(ZEROES, blockLength);
// Serial.println("L:");
// for(i=0;i<blockLength;i++) {
// Serial.printf("%02x", ZEROES[i]);
// }
// Serial.println();
  Lu = new uint8_t[blockLength];
  CMac::doubleLu(ZEROES, Lu, blockLength);
// Serial.println("Lu:");
// for(i=0;i<blockLength;i++) {
// Serial.printf("%02x", Lu[i]);
// }
// Serial.println();
  Lu2 = new uint8_t[blockLength];
  CMac::doubleLu(Lu, Lu2, blockLength);
// Serial.println("Lu2:");
// for(i=0;i<blockLength;i++) {
// Serial.printf("%02x", Lu2[i]);
// }
// Serial.println();

  // ISO7816d4Padding ???
// Serial.println("in:");
// for(i=0;i<blockLength;i++) {
// Serial.printf("%02x", buf[i]);
// }
// Serial.println();
// Serial.println("in2:");
  if (inLength < blockLength) {
// Serial.println("addPadding...");
    buf[inLength] = 0x80;
    for(i=0;i<blockLength;i++) {
// Serial.printf("%02x", buf[i]);
      buf[i] ^= Lu2[i];
    }
  } else {
    for(i=0;i<blockLength;i++) {
// Serial.printf("%02x", buf[i]);
      buf[i] ^= Lu[i];
    }
  }
// Serial.println();
// Serial.println("in3:");
// for(i=0;i<blockLength;i++) {
// Serial.printf("%02x", buf[i]);
// }
// Serial.println();

  cipher->encrypt(buf, blockLength);
// Serial.println("out:");
// for(i=0;i<blockLength;i++) {
// Serial.printf("%02x", buf[i]);
// }
// Serial.println();

  for(i=0;i<blockLength && i<outLength;i++) {
    if (i<blockLength) out[i] = buf[i];
    else out[i] = 0;
  }
  delete Lu;
  delete Lu2;
  delete ZEROES;
  delete buf;
  delete cipher;
  return true;
}

int CMac::shiftLeft(uint8_t in[], uint8_t out[], int size) {
  int i = size;

  int bit = 0;
  while (--i >= 0)
  {
      int b = in[i] & 0xff;
      out[i] = (uint8_t)((b << 1) | bit);
      bit = (b >> 7) & 1;
  }
  return bit;
}

void CMac::doubleLu(uint8_t in[], uint8_t out[], int size) {
  int carry = shiftLeft(in, out, size);
// Serial.println("out@shiftLeft:");
// for(int i=0;i<size;i++) {
// Serial.printf("%02x", out[i]);
// }
// Serial.println();

  /*
    * NOTE: This construction is an attempt at a constant-time implementation.
    */
  int mask = (-carry) & 0xff;
  uint8_t poly[4];
  CMac::lookupPoly(8, poly);
  out[size - 3] ^= poly[1] & mask;
  out[size - 2] ^= poly[2] & mask;
  out[size - 1] ^= poly[3] & mask;
}

void CMac::lookupPoly(uint8_t blockSizeLength, uint8_t out[4]) {
  int XOR;
  switch (blockSizeLength * 8)
  {
  case 64:
    XOR = 0x1B;
    break;
  case 128:
    XOR = 0x87;
    break;
  case 160:
    XOR = 0x2D;
    break;
  case 192:
    XOR = 0x87;
    break;
  case 224:
    XOR = 0x309;
    break;
  case 256:
    XOR = 0x425;
    break;
  case 320:
    XOR = 0x1B;
    break;
  case 384:
    XOR = 0x100D;
    break;
  case 448:
    XOR = 0x851;
    break;
  case 512:
    XOR = 0x125;
    break;
  case 768:
    XOR = 0xA0011;
    break;
  case 1024:
    XOR = 0x80043;
    break;
  case 2048:
    XOR = 0x86001;
    break;
  default:
    break;
  }

  out[0] = (XOR >> 24) & 0xff;
  out[1] = (XOR >> 16) & 0xff;
  out[2] = (XOR >> 8) & 0xff;
  out[3] = (XOR >> 0) & 0xff;
}
