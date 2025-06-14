/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */


#ifndef FLB_OUT_OCI_LOGAN_CONF_H
#define FLB_OUT_OCI_LOGAN_CONF_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>

#include "oci_logan.h"

struct flb_oci_logan *flb_oci_logan_conf_create(struct flb_output_instance *ins,
                                          struct flb_config *config);
int flb_oci_logan_conf_destroy(struct flb_oci_logan *ctx);

flb_sds_t create_federation_payload(struct flb_oci_logan *ctx);
flb_sds_t sign_and_send_federation_request(struct flb_oci_logan *ctx, flb_sds_t payload);
#endif
