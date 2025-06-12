/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_FIPS_INDICATOR_H
# define OPENSSL_FIPS_INDICATOR_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# define OSSL_RH_FIPSINDICATOR_UNAPPROVED (0)
# define OSSL_RH_FIPSINDICATOR_APPROVED (1)

/*
 * FIPS indicator dispatch table element.  function_id numbers and the
 * functions are defined in core_dispatch.h, see macros with
 * 'OSSL_CORE_MAKE_FUNC' in their names.
 *
 * An array of these is always terminated by function_id == 0
 */
typedef struct ossl_rh_fipsindicator_dispatch_st {
    int function_id;
    int approved;
} OSSL_RH_FIPSINDICATOR_DISPATCH;

/*
 * Type to tie together algorithm names, property definition string and the
 * algorithm implementation's FIPS indicator status in the form of a FIPS
 * indicator dispatch table.
 *
 * An array of these is always terminated by algorithm_names == NULL
 */
typedef struct ossl_rh_fipsindicator_algorithm_st {
    const char *algorithm_names;     /* key */
    const char *property_definition; /* key */
    const OSSL_RH_FIPSINDICATOR_DISPATCH *indicators;
} OSSL_RH_FIPSINDICATOR_ALGORITHM;

/**
 * Query FIPS indicator status for the given operation.  Possible values for
 * 'operation_id' are currently only OSSL_OP_SIGNATURE, as all other algorithms
 * use implicit indicators.  The return value is an array of
 * OSSL_RH_FIPSINDICATOR_ALGORITHMs, terminated by an entry with
 * algorithm_names == NULL.  'algorithm_names' is a colon-separated list of
 * algorithm names, 'property_definition' a comma-separated list of properties,
 * and 'indicators' is a list of OSSL_RH_FIPSINDICATOR_DISPATCH structs.  This
 * list is terminated by function_id == 0.  'function_id' is one of the
 * OSSL_FUNC_* constants, e.g., OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL.
 *
 * If there is no entry in the returned struct for the given operation_id,
 * algorithm name, or function_id, the algorithm is unapproved.
 */
const OSSL_RH_FIPSINDICATOR_ALGORITHM *redhat_ossl_query_fipsindicator(int operation_id);

# ifdef __cplusplus
}
# endif

#endif
