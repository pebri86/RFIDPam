#include "spi.h"
#define min(a,b)(a<b?a:b)
//inline int min(int a, int b){return (a<b)?a:b;}

void spi_rw(littleWire *lw, unsigned char *sendData, unsigned char *recvData, size_t len) {
    unsigned char sendBuf[4];
    unsigned char recvBuf[4];

    size_t i;

    for (i = 0; i < len; i += 4) {
        size_t msg_len = min(len - i, 4);

        if (sendData) {
            memcpy(sendBuf, sendData + i, msg_len);
        }
        else {
            memset(sendBuf, 0, msg_len);
        }

#ifdef SPI_DEBUG
        size_t j;

        fprintf(stderr, "SPI Send[%u]:", msg_len);

        for (j = 0; j < msg_len; ++j) {
            fprintf(stderr, " 0x%02x", sendBuf[j]);
        }

        fputs("\n", stderr);
#endif

        spi_sendMessage(lw, sendBuf, recvBuf, msg_len, MANUAL_CS);

        if (lwStatus < 0) {
            fprintf(stderr, "> lwStatus: %d\n", lwStatus);
            fprintf(stderr, "> Connection error!\n");
            exit(EXIT_FAILURE);
        }

#ifdef SPI_DEBUG
        fprintf(stderr, "SPI Recv[%u]:", msg_len);

        for (j = 0; j < msg_len; ++j) {
            fprintf(stderr, " 0x%02x", recvBuf[j]);
        }

        fputs("\n", stderr);
#endif

        if (recvData) {
            memcpy(recvData + i, recvBuf, msg_len);
        }
    }
}
