#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "mfrc522.h"

unsigned char version;

littleWire *littlewire = NULL;

int rc522_check_reader();
uint8_t rc522_read_card_id(uint8_t *card_id, uint16_t *card_type);

int rc522_check_reader()
{
    uint8_t curr_read_status = mfrc522_get_version(littlewire);
    if (curr_read_status == 0x90)
        printf("Found Version 1.0 reader firmware\n");
    else if (curr_read_status == 0x92)
        printf("Found Version 2.0 reader firmware\n");
    else
    {
        printf("NO READER FOUND\n");
        return 1;
    }
    return 0;
}

/*
read card serial id
*/
uint8_t rc522_read_card_id(uint8_t *card_id, uint16_t *card_type)
{
    uint8_t status, resx = 0;
    uint8_t buff_data[MAX_LEN];

    *card_type = 0;
    if(mfrc522_is_card(littlewire, card_type))
    {
        status = mfrc522_get_card_serial(littlewire, buff_data);
        if (status==CARD_FOUND)
        {
            memcpy(card_id,buff_data,5);//kopi id and checksum at last byte (5th)
            resx = 1;
        }
        else
        {
            resx = 0;
        }
    }
    else
    {
        resx = 0;
    }

    return resx;
}

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
    int i, nrounds = 5;
    unsigned char key[32], iv[32];
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
    if (i != 32) return -1;

    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

    return 0;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
    int p_len = *len, f_len = 0;
    unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);

    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
    EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

    *len = p_len + f_len;
    return plaintext;
}


int CheckNFC()
{
    uint8_t curr_id[5];
    uint16_t card_tipe;
    uint8_t str[MAX_LEN];
    uint8_t Status;
    int result;
    EVP_CIPHER_CTX en, de;
    unsigned int salt[] = {12345, 54321};
    unsigned char *key_data;
    FILE *fp;
    int key_data_len;
    char secrettext[] = "Welcome Back Master! Unlocking.";
    char *plaintext;
    long i;
    uint8_t DataBufH[16], DataBufL[16];
    char printable[32];
    unsigned char ciphertext[48];
    int len;

    littlewire = littleWire_connect();
    if(littlewire == NULL)
    {
        printf("> Little Wire could not be found!\n");
        exit(EXIT_FAILURE);
    }

    version = readFirmwareVersion(littlewire);
    printf("> Little Wire firmware version: %d.%d\n",((version & 0xF0)>>4),(version&0x0F));
    if(version==0x10)
    {
        printf("> Requires the new 1.1 version firmware. Please update soon.\n");
        return 0;
    }

    spi_init(littlewire);
    spi_updateDelay(littlewire,0);
    mfrc522_init(littlewire);
    result = rc522_check_reader();
    if(result > 0)
        return 1;

    // read id card
    if (rc522_read_card_id(curr_id, &card_tipe))
    {
        // select the tag
        mfrc522_select_tag(littlewire, curr_id);

        //authenticate to block 1
        mfrc522_auth(littlewire, PICC_AUTHENT1A, 1, keyA_default, curr_id);

        Status = mfrc522_read_block(littlewire, 1, DataBufH);
        if(Status == 1)
        {
            //authenticate to block 2
            mfrc522_auth(littlewire, PICC_AUTHENT1A, 2, keyA_default, curr_id);
            Status = mfrc522_read_block(littlewire, 2, DataBufL);
        }
    }
    else
        return 1;

    if (Status != 1) return 2;

    for (i=0; i<16; i++)
        printable[i] = DataBufH[i];

    uint8_t j = 0;

    for (i=16; i<32; i++)
    {
        printable[i] = DataBufL[j];
        j++;
    }

    printf("%s \n", printable);

    if (aes_init(printable, strlen(printable), (unsigned char *)&salt, &en, &de)) return 2;

    fp = fopen("/etc/MyAuth", "r");
    if (!fp)
    {
        EVP_CIPHER_CTX_cleanup(&en);
        EVP_CIPHER_CTX_cleanup(&de);
        return 3;
    }
    int fr;
    fr = fread(ciphertext, 1, 48, fp);
    if(!fr)
        return 4;
    fclose(fp);
    len =48;
    plaintext = (char *)aes_decrypt(&de, ciphertext, &len);

    if (strcmp(plaintext, secrettext) == 0)
        return 0;
    else
    {

        free(plaintext);
        EVP_CIPHER_CTX_cleanup(&en);
        EVP_CIPHER_CTX_cleanup(&de);
        return 5;
    }


}


PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {

    int retval = CheckNFC();
    if (retval != 0)
    {
        printf("\nNFC Auth Err: %d", retval);
        return PAM_AUTH_ERR;
    }
    else
        return PAM_SUCCESS;
}
