
//
//  PQCgenKAT_kem.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"

#define MAX_MARKER_LEN 50
#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

int FindMarker(FILE *infile, const char *marker);
int ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

int main()
{
    char fn_req[32], fn_rsp[32], fn_keys[32], fn_ctss[32];
    FILE *fp_req, *fp_rsp, *fp_keys, *fp_ctss;
    unsigned char seed[48];
    unsigned char entropy_input[48];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES], ct_new[CRYPTO_CIPHERTEXTBYTES];
    int count;
    int done;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES], pk_new[CRYPTO_PUBLICKEYBYTES];
    int ret_val;



    // Open KEYS file for reading and processing
    sprintf(fn_keys, "PQCkemKAT_1632.keys", CRYPTO_SECRETKEYBYTES);
    if ((fp_keys = fopen(fn_keys, "r")) == NULL)
    {
        printf("Couldn't open <%s> for write\n", fn_keys);
        return KAT_FILE_OPEN_ERROR;
    }

    if (!FindMarker(fp_keys, "count = "))
    {
        printf("ERROR: unable to find 'count' marker in <%s>\n", fn_keys);
        return KAT_DATA_ERROR;
    }

    fscanf(fp_keys, "%d", &count);
    if (!ReadHex(fp_keys, pk_new, CRYPTO_PUBLICKEYBYTES, "pk = "))
    {
        printf("ERROR: unable to read 'pk' from <%s>\n", fn_keys);
        return KAT_DATA_ERROR;
    }

    fclose(fp_keys); // Close the KEYS file after reading

    if ((ret_val = crypto_kem_enc(ct, ss, pk_new)) != 0)
    {
        printf("crypto_kem_enc returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }

    // Write ct and ss to the ctss file
    fprintf(fp_ctss, "count = %d\n", count);
    fprintBstr(fp_ctss, "ct = ", ct, CRYPTO_CIPHERTEXTBYTES);
    fprintBstr(fp_ctss, "ss = ", ss, CRYPTO_BYTES);
        
    fclose(fp_ctss);

    // Now decrypt using values from the ctss file
    if ((fp_ctss = fopen(fn_ctss, "r")) == NULL)
    {
        printf("Couldn't open <%s> for read\n", fn_ctss);
        return KAT_FILE_OPEN_ERROR;
    }

    fscanf(fp_ctss, "%d", &count);
    if (!ReadHex(fp_ctss, ct_new, CRYPTO_CIPHERTEXTBYTES, "ct = "))
    {
        printf("ERROR: unable to read 'ct' from <%s>\n", fn_keys);
        return KAT_DATA_ERROR;
    }

    
    
    if ((ret_val = crypto_kem_dec(ss1, ct_new, sk)) != 0)
    {
        printf("crypto_kem_dec returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }

    if (memcmp(ss, ss1, CRYPTO_BYTES))
    {
        printf("crypto_kem_dec returned bad 'ss' value\n");
        return KAT_CRYPTO_FAILURE;
    }
    

    fclose(fp_ctss);

    return KAT_SUCCESS;
}



//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
	char	line[MAX_MARKER_LEN];
	int		i, len;
	int curr_line;

	len = (int)strlen(marker);
	if ( len > MAX_MARKER_LEN-1 )
		len = MAX_MARKER_LEN-1;

	for ( i=0; i<len; i++ )
	  {
	    curr_line = fgetc(infile);
	    line[i] = curr_line;
	    if (curr_line == EOF )
	      return 0;
	  }
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) )
			return 1;

		for ( i=0; i<len-1; i++ )
			line[i] = line[i+1];
		curr_line = fgetc(infile);
		line[len-1] = curr_line;
		if (curr_line == EOF )
		    return 0;
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
	int			i, ch, started;
	unsigned char	ich;

	if ( Length == 0 ) {
		A[0] = 0x00;
		return 1;
	}
	memset(A, 0x00, Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' )
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') )
				ich = ch - '0';
			else if ( (ch >= 'A') && (ch <= 'F') )
				ich = ch - 'A' + 10;
			else if ( (ch >= 'a') && (ch <= 'f') )
				ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;

			for ( i=0; i<Length-1; i++ )
				A[i] = (A[i] << 4) | (A[i+1] >> 4);
			A[Length-1] = (A[Length-1] << 4) | ich;
		}
	else
		return 0;

	return 1;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

