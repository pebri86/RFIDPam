#ifndef __SPI_H__
#define __SPI_H__

#include "littleWire.h"
#include <stdlib.h>

//#define SPI_DEBUG

void spi_rw(littleWire *lw, unsigned char *sendData, unsigned char *recvData, size_t len);

#endif
