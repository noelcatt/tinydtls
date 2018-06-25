/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RLWEModule"
 * 	found in "./rlweModule.asn1"
 * 	`asn1c -fincludes-quoted`
 */

#ifndef	_RLWEAlgorithm_H_
#define	_RLWEAlgorithm_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RLWEAlgorithm */
typedef struct RLWEAlgorithm {
	OBJECT_IDENTIFIER_t	 pub;
	OBJECT_IDENTIFIER_t	 kem;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RLWEAlgorithm_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RLWEAlgorithm;

#ifdef __cplusplus
}
#endif

#endif	/* _RLWEAlgorithm_H_ */
#include "asn_internal.h"
