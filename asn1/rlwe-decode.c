#include <stdio.h> /* for stdout */ 
#include <stdlib.h> /* for malloc() */ 
#include <assert.h> /* for run-time control */ 
#include "RLWECert.h" /* Include MyTypes definition */ 

int main(int argc, char *argv[]) { 
	
	RLWECert_t *cert = 0;
	char *buf[4096];
	asn_dec_rval_t rval;
	char *filename;
	size_t size;
	FILE *f;
	int i;

	int *oid_array;
	int oid_size;
	uint8_t *cert_data;
	int cert_size;

	/*
	 * Read in the input file.
	 */
	assert(argc == 2);
	filename = argv[1];
	f = fopen(filename, "r");
	assert(f);
	size = fread(buf, 1, sizeof buf, f);
	if(size == 0 || size == sizeof buf) {
		fprintf(stderr, "%s: Too large input\n", filename);
		exit(1);
	}

	/*
	 * Decode the XER buffer.
	 */
	//rval = xer_decode(0, &asn_DEF_RLWECert, &cert, buf, size);
	//assert(rval.code == RC_OK);

	/*
	 * Decode the BER buffer.
	 */
	rval = ber_decode(0, &asn_DEF_RLWECert, (void **)&cert, buf, size);
	assert(rval.code == RC_OK);

	/*
	 * Convert the OBJECT IDENTIFIER into oid_array/oid_size pair.
	 */
	/* Figure out the number of arcs inside OBJECT IDENTIFIER */
	oid_size = OBJECT_IDENTIFIER_get_arcs(&(cert->alg.pub),
			0, sizeof(oid_array[0]), 0);
	assert(oid_size >= 0);
	/* Create the array of arcs and fill it in */
	oid_array = malloc(oid_size * sizeof(oid_array[0]));
	assert(oid_array);
	(void)OBJECT_IDENTIFIER_get_arcs(&(cert->alg.pub),
			oid_array, sizeof(oid_array[0]), oid_size);

	for (i = 0; i < oid_size; i++)
	{
		printf ("%d ", oid_array[i]) ;
	}
	printf("\n");

	for (i = 0; i < cert->data.size; i++)
	{
		unsigned char c = ((char*)buf)[i] ;
		printf ("%02x ", c) ;
	}
	printf("\n");

	return 0; 
}
