#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
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

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);

	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);
	*len = c_len + f_len;
	return ciphertext;
}

int main(int argc, char **argv)
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
	int key_data_len, i;
	char *input[] = {"Welcome Back Master! Unlocking.",NULL};
	char *plaintext;
	unsigned char *ciphertext;
	int len, olen;

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
	
	if (argc != 2) 
	{
		printf("Please enter a 32-byte key string as parameter\n");
		return -1;
	}
	if (strlen(argv[1]) != 32)
	{
		printf("Please enter a 32-byte key string as parameter\n");
		return -1;
	}
	
	key_data = (unsigned char *)argv[1];
	key_data_len = strlen(argv[1]);
  
	if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) 
	{
		printf("Couldn't initialize AES cipher\n");
		return -1;
	}

	olen = len = strlen(input[0])+1;
   	ciphertext = aes_encrypt(&en, (unsigned char *)input[0], &len);

    	fp = fopen("/etc/MyAuth", "w");
	if (!fp)
	{
		printf("Failed to open MyAuth file. Are you running as root?\n");
		return -1;
	}

	fwrite(ciphertext, 1, 48, fp);
	fclose(fp);
	
	printf("MyAuth file has been created successfully\n");

	uint8_t DataBuf[32], DataBufH[16], DataBufL[16];
	for (i=0;i<32;i++)
		DataBuf[i] = argv[1][i];

	for (i=0;i<16;i++)
	{
		DataBufH[i] = DataBuf[i];
	}

	uint8_t j = 0;
	for (i=16;i<32;i++)
	{
		DataBufL[j] = DataBuf[i];
		j++;
	}
	
	// read id card
	if (rc522_read_card_id(curr_id, &card_tipe))
    {
		// printf("%.2X%.2X%.2X%.2X%.2X %.4X\n", curr_id[0], curr_id[1], curr_id[2], curr_id[3], curr_id[4], card_tipe);

        // select the tag
        printf("select = %.2X\n", mfrc522_select_tag(littlewire, curr_id));

        //login to block 1
        printf("login = %d\n", mfrc522_auth(littlewire, PICC_AUTHENT1A, 1, keyA_default, curr_id));

		Status = mfrc522_write_block(littlewire, 1, DataBufH);
		if(Status == 1)
		{
			//login to block 2
        	printf("login = %d\n", mfrc522_auth(littlewire, PICC_AUTHENT1A, 2, keyA_default, curr_id));
			Status = mfrc522_write_block(littlewire, 2, DataBufL);
		}
	}

	if (Status == 1)
	{
		printf("\nKey written to RFID card successfully!\n");
		printf("\nNow compile and install NFCMyAuth module\n");
		printf("\nThen add \"auth required NFCMyAuth.so\" into PAM file\n");
	}
	else
		printf("\nFailed to write to card! Error: %d\n", i);
	
	free(ciphertext);

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);
	return 0;
}
  
