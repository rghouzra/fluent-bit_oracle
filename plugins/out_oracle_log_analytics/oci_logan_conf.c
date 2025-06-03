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


#include <sys/stat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_file.h>

#include <monkey/mk_core/mk_list.h>
#include <monkey/mk_core/mk_string.h>
#include <fluent-bit/flb_utils.h>

#include "oci_logan.h"
#include "oci_logan_conf.h"

static int create_pk_context(flb_sds_t filepath, const char *key_passphrase,
                             struct flb_oci_logan *ctx)
{
    int ret;
    struct stat st;
    struct file_info finfo;
    FILE *fp;
    flb_sds_t kbuffer;


    ret = stat(filepath, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open key file %s", filepath);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "key file is not a valid file: %s", filepath);
        return -1;
    }

    /* Read file content */
    if (mk_file_get_info(filepath, &finfo, MK_FILE_READ) != 0) {
        flb_plg_error(ctx->ins, "error to read key file: %s", filepath);
        return -1;
    }

    if (!(fp = fopen(filepath, "rb"))) {
        flb_plg_error(ctx->ins, "error to open key file: %s", filepath);
        return -1;
    }

    kbuffer = flb_sds_create_size(finfo.size + 1);
    if (!kbuffer) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    ret = fread(kbuffer, finfo.size, 1, fp);
    if (ret < 1) {
        flb_sds_destroy(kbuffer);
        fclose(fp);
        flb_plg_error(ctx->ins, "fail to read key file: %s", filepath);
        return -1;
    }
    fclose(fp);

    /* In mbedtls, for PEM, the buffer must contains a null-terminated string */
    kbuffer[finfo.size] = '\0';
    flb_sds_len_set(kbuffer, finfo.size + 1);

    ctx->private_key = kbuffer;

    return 0;
}

static int load_oci_credentials(struct flb_oci_logan *ctx)
{
    flb_sds_t content;
    int found_profile = 0, res = 0;
    char *line, *profile = NULL;
    int eq_pos = 0;
    char *key = NULL;
    char *val;

    content = flb_file_read(ctx->config_file_location);
    if (content == NULL || flb_sds_len(content) == 0) {
        return -1;
    }
    flb_plg_debug(ctx->ins, "content = %s", content);
    line = strtok(content, "\n");
    while (line != NULL) {
        /* process line */
        flb_plg_debug(ctx->ins, "line = %s", line);
        if (!found_profile && line[0] == '[') {
            profile = mk_string_copy_substr(line, 1, strlen(line) - 1);
            if (!strcmp(profile, ctx->profile_name)) {
                flb_plg_info(ctx->ins, "found profile");
                found_profile = 1;
                goto iterate;
            }
            mk_mem_free(profile);
            profile = NULL;
        }
        if (found_profile) {
            if (line[0] == '[') {
                break;
            }
            eq_pos = mk_string_char_search(line, '=', strlen(line));
            flb_plg_debug(ctx->ins, "eq_pos %d", eq_pos);
            key = mk_string_copy_substr(line, 0, eq_pos);
            flb_plg_debug(ctx->ins, "key = %s", key);
            val = line + eq_pos + 1;
            if (!key || !val) {
                res = -1;
                break;
            }
            if (strcmp(key, FLB_OCI_PARAM_USER) == 0) {
                ctx->user = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_TENANCY) == 0) {
                ctx->tenancy = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FILE) == 0) {
                ctx->key_file = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FINGERPRINT) == 0) {
                ctx->key_fingerprint = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_REGION) == 0) {
                ctx->region = flb_sds_create(val);
            }
            else {
                goto iterate;
            }
        }
      iterate:
        if (profile) {
            mk_mem_free(profile);
            profile = NULL;
        }
        if (key) {
            mk_mem_free(key);
            key = NULL;
        }
        line = strtok(NULL, "\n");
    }
    if (!found_profile) {
        flb_errno();
        res = -1;
    }

    flb_sds_destroy(content);
    if (profile) {
        mk_mem_free(profile);
    }
    if (key) {
        mk_mem_free(key);
    }
    return res;
}

static int global_metadata_fields_create(struct flb_oci_logan *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *val;
    struct flb_config_map_val *mv;
    struct metadata_obj *f;

    if (!ctx->oci_la_global_metadata) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->oci_la_global_metadata) {
        kname =
            mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct metadata_obj));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key = flb_sds_create(kname->str);
        if (!f->key) {
            flb_free(f);
            return -1;
        }
        f->val = flb_sds_create(val->str);
        if (!f->val) {
            flb_sds_destroy(f->key);
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->global_metadata_fields);
    }

    return 0;
}

static int log_event_metadata_create(struct flb_oci_logan *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *val;
    struct flb_config_map_val *mv;
    struct metadata_obj *f;

    if (!ctx->oci_la_metadata) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->oci_la_metadata) {
        kname =
            mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct metadata_obj));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key = flb_sds_create(kname->str);
        if (!f->key) {
            flb_free(f);
            return -1;
        }
        f->val = flb_sds_create(val->str);
        if (!f->val) {
            flb_sds_destroy(f->key);
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->log_event_metadata_fields);
    }

    return 0;
}

static flb_sds_t make_imds_request(struct flb_oci_logan *ctx,
                                   struct flb_connection *u_conn,
                                   const char *path)
{
    struct flb_http_client *client;
    flb_sds_t response = NULL;
    size_t b_sent;
    int ret;

    flb_plg_debug(ctx->ins, "path->%s", path);
    client = flb_http_client(u_conn, FLB_HTTP_GET, path, NULL, 0,
                             ORACLE_IMDS_HOST, 80, NULL, 0);
    if (!client) {
        return NULL;
    }

    flb_http_add_header(client, "Authorization", 13, "Bearer Oracle", 13);
    ret = flb_http_do(client, &b_sent);
    if (ret != 0 || client->resp.status != 200) {
        flb_http_client_destroy(client);
        return NULL;
    }

    response = flb_sds_create_len(client->resp.data, client->resp.data_len);
    flb_http_client_destroy(client);
    return response;
}

static const region_mapping_t region_mappings[] = {
    {"yny", "ap-chuncheon-1"},
    {"hyd", "ap-hyderabad-1"},
    {"mel", "ap-melbourne-1"},
    {"bom", "ap-mumbai-1"},
    {"kix", "ap-osaka-1"},
    {"icn", "ap-seoul-1"},
    {"syd", "ap-sydney-1"},
    {"nrt", "ap-tokyo-1"},
    {"yul", "ca-montreal-1"},
    {"yyz", "ca-toronto-1"},
    {"ams", "eu-amsterdam-1"},
    {"fra", "eu-frankfurt-1"},
    {"zrh", "eu-zurich-1"},
    {"jed", "me-jeddah-1"},
    {"dxb", "me-dubai-1"},
    {"gru", "sa-saopaulo-1"},
    {"cwl", "uk-cardiff-1"},
    {"lhr", "uk-london-1"},
    {"iad", "us-ashburn-1"},
    {"phx", "us-phoenix-1"},
    {"sjc", "us-sanjose-1"},
    {"vcp", "sa-vinhedo-1"},
    {"scl", "sa-santiago-1"},
    {"mtz", "il-jerusalem-1"},
    {"mrs", "eu-marseille-1"},
    {"sin", "ap-singapore-1"},
    {"auh", "me-abudhabi-1"},
    {"lin", "eu-milan-1"},
    {"arn", "eu-stockholm-1"},
    {"jnb", "af-johannesburg-1"},
    {"cdg", "eu-paris-1"},
    {"qro", "mx-queretaro-1"},
    {"mad", "eu-madrid-1"},
    {"ord", "us-chicago-1"},
    {"mty", "mx-monterrey-1"},
    {"aga", "us-saltlake-2"},
    {"bog", "sa-bogota-1"},
    {"vap", "sa-valparaiso-1"},
    {"xsp", "ap-singapore-2"},
    {"ruh", "me-riyadh-1"},
    {"lfi", "us-langley-1"},
    {"luf", "us-luke-1"},
    {"ric", "us-gov-ashburn-1"},
    {"pia", "us-gov-chicago-1"},
    {"tus", "us-gov-phoenix-1"},
    {"ltn", "uk-gov-london-1"},
    {"brs", "uk-gov-cardiff-1"},
    {"nja", "ap-chiyoda-1"},
    {"ukb", "ap-ibaraki-1"},
    {"mct", "me-dcc-muscat-1"},
    {"wga", "ap-dcc-canberra-1"},
    {"bgy", "eu-dcc-milan-1"},
    {"mxp", "eu-dcc-milan-2"},
    {"snn", "eu-dcc-dublin-2"},
    {"dtm", "eu-dcc-rating-2"},
    {"dus", "eu-dcc-rating-1"},
    {"ork", "eu-dcc-dublin-1"},
    {"dac", "ap-dcc-gazipur-1"},
    {"vll", "eu-madrid-2"},
    {"str", "eu-frankfurt-2"},
    {"beg", "eu-jovanovac-1"},
    {"doh", "me-dcc-doha-1"},
    {"ebb", "us-somerset-1"},
    {"ebl", "us-thames-1"},
    {"avz", "eu-dcc-zurich-1"},
    {"avf", "eu-crissier-1"},
    {"ahu", "me-abudhabi-3"},
    {"rba", "me-alain-1"},
    {"rkt", "me-abudhabi-2"},
    {"shj", "me-abudhabi-4"},
    {"dtz", "ap-seoul-2"},
    {"dln", "ap-suwon-1"},
    {"bno", "ap-chuncheon-2"},
    {NULL, NULL}
};

static const realm_mapping_t realm_mappings[] = {
    {"oc1", "oraclecloud.com"},
    {"oc2", "oraclegovcloud.com"},
    {"oc3", "oraclegovcloud.com"},
    {"oc4", "oraclegovcloud.uk"},
    {"oc8", "oraclecloud8.com"},
    {"oc9", "oraclecloud9.com"},
    {"oc10", "oraclecloud10.com"},
    {"oc14", "oraclecloud14.com"},
    {"oc15", "oraclecloud15.com"},
    {"oc19", "oraclecloud.eu"},
    {"oc20", "oraclecloud20.com"},
    {"oc21", "oraclecloud21.com"},
    {"oc23", "oraclecloud23.com"},
    {"oc24", "oraclecloud24.com"},
    {"oc26", "oraclecloud26.com"},
    {"oc29", "oraclecloud29.com"},
    {"oc35", "oraclecloud35.com"},
    {NULL, NULL}
};

//ref--> github.com/oracle/oci-python-sdk/blob/ba91eb1a51b0c1a38603dec0373a33f9b9962f8a/src/oci/regions_definitions.py 
// still  it have to be updated depending on new oraclecloudXX

static const region_realm_mapping_t region_realm_mappings[] = {
    {"ap-chuncheon-1", "oc1"},
    {"ap-hyderabad-1", "oc1"},
    {"ap-melbourne-1", "oc1"},
    {"ap-mumbai-1", "oc1"},
    {"ap-osaka-1", "oc1"},
    {"ap-seoul-1", "oc1"},
    {"ap-sydney-1", "oc1"},
    {"ap-tokyo-1", "oc1"},
    {"ca-montreal-1", "oc1"},
    {"ca-toronto-1", "oc1"},
    {"eu-amsterdam-1", "oc1"},
    {"eu-frankfurt-1", "oc1"},
    {"eu-zurich-1", "oc1"},
    {"me-jeddah-1", "oc1"},
    {"me-dubai-1", "oc1"},
    {"sa-saopaulo-1", "oc1"},
    {"uk-cardiff-1", "oc1"},
    {"uk-london-1", "oc1"},
    {"us-ashburn-1", "oc1"},
    {"us-phoenix-1", "oc1"},
    {"us-sanjose-1", "oc1"},
    {"sa-vinhedo-1", "oc1"},
    {"sa-santiago-1", "oc1"},
    {"il-jerusalem-1", "oc1"},
    {"eu-marseille-1", "oc1"},
    {"ap-singapore-1", "oc1"},
    {"me-abudhabi-1", "oc1"},
    {"eu-milan-1", "oc1"},
    {"eu-stockholm-1", "oc1"},
    {"af-johannesburg-1", "oc1"},
    {"eu-paris-1", "oc1"},
    {"mx-queretaro-1", "oc1"},
    {"eu-madrid-1", "oc1"},
    {"us-chicago-1", "oc1"},
    {"mx-monterrey-1", "oc1"},
    {"us-saltlake-2", "oc1"},
    {"sa-bogota-1", "oc1"},
    {"sa-valparaiso-1", "oc1"},
    {"ap-singapore-2", "oc1"},
    {"me-riyadh-1", "oc1"},
    {"us-langley-1", "oc2"},
    {"us-luke-1", "oc2"},
    {"us-gov-ashburn-1", "oc3"},
    {"us-gov-chicago-1", "oc3"},
    {"us-gov-phoenix-1", "oc3"},
    {"uk-gov-london-1", "oc4"},
    {"uk-gov-cardiff-1", "oc4"},
    {"ap-chiyoda-1", "oc8"},
    {"ap-ibaraki-1", "oc8"},
    {"me-dcc-muscat-1", "oc9"},
    {"ap-dcc-canberra-1", "oc10"},
    {"eu-dcc-milan-1", "oc14"},
    {"eu-dcc-milan-2", "oc14"},
    {"eu-dcc-dublin-2", "oc14"},
    {"eu-dcc-rating-2", "oc14"},
    {"eu-dcc-rating-1", "oc14"},
    {"eu-dcc-dublin-1", "oc14"},
    {"ap-dcc-gazipur-1", "oc15"},
    {"eu-madrid-2", "oc19"},
    {"eu-frankfurt-2", "oc19"},
    {"eu-jovanovac-1", "oc20"},
    {"me-dcc-doha-1", "oc21"},
    {"us-somerset-1", "oc23"},
    {"us-thames-1", "oc23"},
    {"eu-dcc-zurich-1", "oc24"},
    {"eu-crissier-1", "oc24"},
    {"me-abudhabi-3", "oc26"},
    {"me-alain-1", "oc26"},
    {"me-abudhabi-2", "oc29"},
    {"me-abudhabi-4", "oc29"},
    {"ap-seoul-2", "oc35"},
    {"ap-suwon-1", "oc35"},
    {"ap-chuncheon-2", "oc35"},
    {NULL, NULL}
};

static const char *determine_realm_from_region(const char *region)
{
    if (!region) {
        return "oc1";
    }

    for (int i = 0; region_realm_mappings[i].region != NULL; i++) {
        if (strcmp(region, region_realm_mappings[i].region) == 0) {
            return region_realm_mappings[i].realm;
        }
    }
    return "oc1";
}

static const char *get_domain_suffix_for_realm(const char *realm)
{
    if (!realm) {
        return "oraclecloud.com";
    }

    for (int i = 0; realm_mappings[i].realm_code != NULL; i++) {
        if (strcmp(realm, realm_mappings[i].realm_code) == 0) {
            return realm_mappings[i].domain_suffix;
        }
    }

    return "oraclecloud.com";
}

static flb_sds_t construct_oci_host(const char *service, const char *region)
{
    if (!service || !region) {
        return NULL;
    }

    const char *realm = determine_realm_from_region(region);
    const char *domain_suffix = get_domain_suffix_for_realm(realm);
    fprintf(stderr, "construct_oci_host::realm->[%s]\n", realm);
    fprintf(stderr, "construct_oci_host::domain_suffix->[%s]\n",
            domain_suffix);

    flb_sds_t host = flb_sds_create_size(256);
    if (!host) {
        return NULL;
    }

    flb_sds_snprintf(&host, flb_sds_alloc(host), "%s.%s.oci.%s",
                     service, region, domain_suffix);
    // fprintf(stderr, "construct_oci_host::host->[%s]\n", host);
    return host;
}

const char *long_region_name(char *short_region_name)
{
    for (size_t i = 0; i < COUNT_OF_REGION; i++) {
        if (strcmp(short_region_name, region_mappings[i].short_name) == 0) {
            return (region_mappings[i].long_name);
        }
    }
    return NULL;
}

flb_sds_t extract_region(const char *response)
{
    const char *body_start = strstr(response, "\r\n\r\n");
    if (!body_start) {
        return NULL;
    }

    body_start += 4;

    while (*body_start == '\n' || *body_start == '\r' || *body_start == ' ') {
        body_start++;
    }

    size_t len = strlen(body_start);
    while (len > 0
           && (body_start[len - 1] == '\n' || body_start[len - 1] == '\r'
               || body_start[len - 1] == ' ')) {
        len--;
    }

    char *region = malloc(len + 1);
    if (!region) {
        return NULL;
    }

    strncpy(region, body_start, len);
    region[len] = '\0';
    flb_sds_t lregion = flb_sds_create(long_region_name(region));       // should be freed later
    free(region);
    return lregion;
}

char *extract_pem_content(const char *response, const char *begin_marker,
                          const char *end_marker)
{
    const char *start = strstr(response, begin_marker);
    if (!start) {
        return NULL;
    }

    const char *end = strstr(start, end_marker);
    if (!end) {
        return NULL;
    }

    end += strlen(end_marker);

    size_t pem_length = end - start;
    char *pem_content = flb_calloc(pem_length + 1, 1);
    if (!pem_content) {
        return NULL;
    }

    strncpy(pem_content, start, pem_length);

    return pem_content;
}

flb_sds_t calculate_certificate_fingerprint(struct flb_oci_logan *ctx,
                                            const char *cert_pem)
{
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    X509 *cert = NULL;
    BIO *bio = NULL;
    flb_sds_t fingerprint = NULL;

    bio = BIO_new_mem_buf(cert_pem, -1);
    if (!bio) {
        return NULL;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bio);
        return NULL;
    }

    unsigned char *der_cert = NULL;
    int der_len = i2d_X509(cert, &der_cert);
    if (der_len <= 0 || !der_cert) {
        X509_free(cert);
        BIO_free(bio);
        return NULL;
    }

    SHA1(der_cert, der_len, sha1_hash);
    OPENSSL_free(der_cert);

    char hex_fingerprint[SHA_DIGEST_LENGTH * 3 + 1];
    char *p = hex_fingerprint;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        p += sprintf(p, "%02x:", sha1_hash[i]);
    }

    if (p > hex_fingerprint) {
        *(p - 1) = '\0';
    }

    fingerprint = flb_sds_create(hex_fingerprint);      // should be freed later

    for (int i = 0; i < flb_sds_len(fingerprint); i++) {
        if (islower(fingerprint[i])) {
            fingerprint[i] = toupper(fingerprint[i]);
        }

    }
    X509_free(cert);
    BIO_free(bio);

    return fingerprint;
}

bool extract_tenancy_ocid(struct flb_oci_logan *ctx, const char *cert_pem)
{
    BIO *bio = BIO_new_mem_buf(cert_pem, -1);
    if (!bio) {
        return 0;
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) {
        return 0;
    }

    flb_sds_t tenancy_ocid = NULL;
    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject) {
        char buf[1024];
        X509_NAME_oneline(subject, buf, sizeof(buf));
    }

    int entry_count = X509_NAME_entry_count(subject);
    for (int i = 0; i < entry_count; i++) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, i);
        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
        if (OBJ_obj2nid(obj) == NID_organizationalUnitName) {
            ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
            const char *ou_str = (const char *) ASN1_STRING_get0_data(data);

            if (strstr(ou_str, "opc-tenant:ocid1.tenancy") == ou_str) {
                const char *ocid = strchr(ou_str, ':');
                if (ocid && strlen(ocid + 1) > 0) {
                    tenancy_ocid = flb_sds_create(ocid + 1);    // should be freed later
                    break;
                }
            }
        }
    }

    X509_free(cert);

    if (!tenancy_ocid) {
        return 0;
    }

    ctx->imds.tenancy_ocid = tenancy_ocid;
    return 1;
}

int get_keys_and_certs(struct flb_oci_logan *ctx, struct flb_config *config)
{
    ctx->u =
        flb_upstream_create(config, ORACLE_IMDS_HOST, 80, FLB_IO_TCP, NULL);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "failed to create upstream");
        return 0;
    }

    struct flb_connection *u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "failed to get upstream connection");
        return 0;
    }
    flb_sds_t region_resp =
        make_imds_request(ctx, u_conn,
                          ORACLE_IMDS_BASE_URL ORACLE_IMDS_REGION_PATH);
    if (!region_resp) {
        flb_plg_error(ctx->ins, "failed to get region from IMDS");
        goto error;
    }
    flb_sds_t cert_resp =
        make_imds_request(ctx, u_conn,
                          ORACLE_IMDS_BASE_URL ORACLE_IMDS_LEAF_CERT_PATH);
    if (!cert_resp) {
        flb_plg_error(ctx->ins, "failed to get leaf certificate from IMDS");
        goto error;
    }
    flb_sds_t key_resp = make_imds_request(ctx, u_conn, ORACLE_IMDS_BASE_URL ORACLE_IMDS_LEAF_KEY_PATH);        // should be freed later
    if (!key_resp) {
        flb_plg_error(ctx->ins, "failed to get leaf key from IMDS");
        goto error;
    }
    flb_sds_t int_cert_resp = make_imds_request(ctx, u_conn, ORACLE_IMDS_BASE_URL ORACLE_IMDS_INTERMEDIATE_CERT_PATH);  // should be freed later
    if (!int_cert_resp) {
        flb_plg_error(ctx->ins,
                      "failed to get intermediate certificate from IMDS");
        goto error;
    }
    flb_sds_t clean_region_resp = extract_region(region_resp);
    flb_sds_destroy(region_resp);

    char *clean_cert_resp = extract_pem_content(cert_resp, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"); // should be freed later
    flb_sds_destroy(cert_resp);

    ctx->imds.region = clean_region_resp;
    flb_plg_debug(ctx->ins, "ctx->imds->region %s", ctx->imds.region);
    ctx->imds.leaf_cert = clean_cert_resp;
    ctx->imds.intermediate_cert = int_cert_resp;
    char *pem_start = strstr(key_resp, "-----BEGIN");
    char *pem_end = strstr(key_resp, "-----END");
    if (!pem_start || !pem_end) {
        flb_plg_error(ctx->ins, "No valid PEM block found");
        goto error;
    }
    size_t pem_len =
        (pem_end - pem_start) + strlen("-----END RSA PRIVATE KEY-----") + 1;
    ctx->imds.leaf_key = flb_sds_create_len(pem_start, pem_len);        // should be freed later

    if (!extract_tenancy_ocid(ctx, clean_cert_resp)) {
        flb_plg_error(ctx->ins, "extract_tenancy_ocid failed");
        goto error;
    }
    ctx->imds.fingerprint =
        calculate_certificate_fingerprint(ctx, clean_cert_resp);
    if (!ctx->imds.fingerprint) {
        flb_plg_error(ctx->ins, "calculate_certificate_fingerprint failed");
        goto error;
    }
    flb_upstream_conn_release(u_conn);
    flb_upstream_destroy(ctx->u);
    ctx->u = NULL;
    return 1;

  error:
    if (region_resp) {
        flb_sds_destroy(region_resp);
    }
    if (cert_resp) {
        flb_sds_destroy(cert_resp);;
    }
    if (key_resp) {
        flb_sds_destroy(key_resp);
    }
    if (int_cert_resp) {
        flb_sds_destroy(int_cert_resp);
    }
    ctx->imds.intermediate_cert = NULL;
    ctx->imds.leaf_cert = NULL;
    ctx->imds.leaf_key = NULL;
    ctx->imds.region = NULL;
    flb_upstream_conn_release(u_conn);
    flb_upstream_destroy(ctx->u);
    ctx->u = NULL;
    flb_plg_error(ctx->ins, "error: bloacl");
    return 0;
}

static EVP_PKEY *generate_session_key_pair(struct flb_oci_logan *ctx)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    BIGNUM *bn = BN_new();
    // it still to be updated since its deprecated after openssl 3.0
    RSA *rsa = RSA_new();
    int rc;

    BN_set_word(bn, RSA_F4);
    rc = RSA_generate_key_ex(rsa, 2048, bn, NULL);
    if (rc != 1) {
        RSA_free(rsa);
        BN_free(bn);
        return NULL;
    }

    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);
    return pkey;
}


char *extract_public_key_pem(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return NULL;
    }


    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        return NULL;
    }


    char *pem_data = NULL;
    long pem_length = BIO_get_mem_data(bio, &pem_data);


    char *public_key_pem = malloc(pem_length + 1);
    if (!public_key_pem) {
        BIO_free(bio);
        return NULL;
    }

    strncpy(public_key_pem, pem_data, pem_length);
    public_key_pem[pem_length] = '\0';

    BIO_free(bio);
    return public_key_pem;
}

char *extract_private_key_pem(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return NULL;
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(bio);
        return NULL;
    }


    char *pem_data = NULL;
    long pem_length = BIO_get_mem_data(bio, &pem_data);


    char *private_key_pem = malloc(pem_length + 1);
    if (!private_key_pem) {
        BIO_free(bio);
        return NULL;
    }

    strncpy(private_key_pem, pem_data, pem_length);
    private_key_pem[pem_length] = '\0';

    BIO_free(bio);
    return private_key_pem;
}

static flb_sds_t sanitize_certificate(const char *cert_str)
{
    if (!cert_str)
        return NULL;

    const char *start = strstr(cert_str, "-----BEGIN");
    if (!start)
        return NULL;

    start = strchr(start, '\n');
    if (!start)
        return NULL;
    start++;

    const char *end = strstr(cert_str, "-----END");
    if (!end || end <= start)
        return NULL;

    flb_sds_t clean = flb_sds_create_len(start, end - start);
    if (!clean)
        return NULL;

    size_t j = 0;
    for (size_t i = 0; i < flb_sds_len(clean); i++) {
        if (!isspace(clean[i])) {
            clean[j++] = clean[i];
        }
    }
    clean[j] = '\0';
    flb_sds_len_set(clean, j);

    return clean;
}

flb_sds_t create_federation_payload(struct flb_oci_logan *ctx)
{
    flb_sds_t payload = NULL;
    flb_sds_t leaf_cert = sanitize_certificate(ctx->imds.leaf_cert);    // should be freed later
    flb_sds_t session_pubkey = sanitize_certificate(ctx->imds.session_pubkey);
    flb_sds_t intermediate_certs = sanitize_certificate(ctx->imds.intermediate_cert);   // should be freed later

    if (ctx->imds.intermediate_cert) {
        intermediate_certs = sanitize_certificate(ctx->imds.intermediate_cert); // should be freed later
    }

    payload = flb_sds_create_size(8192);
    if (!payload) {
        goto cleanup;
    }

    if (intermediate_certs && flb_sds_len(intermediate_certs) > 0) {
        flb_sds_printf(&payload,
                       "{\"certificate\":\"%s\",\"publicKey\":\"%s\","
                       "\"intermediateCertificates\":[\"%s\"]}",
                       leaf_cert, session_pubkey, intermediate_certs);
    }
    else {
        flb_sds_printf(&payload,
                       "{\"certificate\":\"%s\",\"publicKey\":\"%s\","
                       "\"intermediateCertificates\":[]}",
                       leaf_cert, session_pubkey);
    }


  cleanup:
    // flb_sds_destroy(leaf_cert);
    // flb_sds_destroy(session_pubkey);
    // flb_sds_destroy(intermediate_certs);
    return payload;
}

static flb_sds_t sign_request_with_key(struct flb_oci_logan *ctx,
                                       const char *method,
                                       flb_sds_t url_path,
                                       flb_sds_t payload,
                                       flb_sds_t date, const char *host)
{
    flb_sds_t auth_header = NULL;
    flb_sds_t string_to_sign = NULL;
    flb_sds_t lowercase_method = NULL;
    unsigned char *signature = NULL;
    unsigned char *b64_out = NULL;
    size_t sig_len = 0;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;

    string_to_sign = flb_sds_create_size(1024);
    if (!string_to_sign) {
        return NULL;
    }

    lowercase_method = flb_sds_create(method);
    if (!lowercase_method) {
        flb_sds_destroy(string_to_sign);
        return NULL;
    }

    for (int i = 0; i < flb_sds_len(lowercase_method); i++) {
        lowercase_method[i] = tolower(method[i]);
    }

    flb_sds_printf(&string_to_sign, "date: %s\n", date);
    flb_sds_printf(&string_to_sign, "(request-target): %s %s\n",
                   lowercase_method, url_path);
    // flb_sds_printf(&string_to_sign, "host: %s\n", host);
    flb_sds_printf(&string_to_sign, "content-length: %zu\n",
                   (payload) ? strlen(payload) : 0);
    flb_sds_printf(&string_to_sign, "content-type: application/json\n");

    unsigned char hash[SHA256_DIGEST_LENGTH];
    char *b64_hash = NULL;
    size_t b64_len = 0;

    SHA256((unsigned char *) payload, (payload) ? flb_sds_len(payload) : 0,
           hash);

    b64_len = 4 * ((SHA256_DIGEST_LENGTH + 2) / 3) + 1;
    b64_hash = flb_malloc(b64_len);
    if (!b64_hash) {
        goto cleanup;
    }
    if (flb_base64_encode
        ((unsigned char *) b64_hash, b64_len, &b64_len, hash,
         SHA256_DIGEST_LENGTH) != 0) {
        flb_free(b64_hash);
        goto cleanup;
    }
    b64_hash[b64_len] = '\0';

    flb_sds_printf(&string_to_sign, "x-content-sha256: %s", b64_hash);

    if (b64_hash) {
        flb_free(b64_hash);
    }
    flb_plg_debug(ctx->ins, "string to sign: [%s]", string_to_sign);

    bio = BIO_new_mem_buf((void *) ctx->imds.leaf_key, -1);
    if (!bio) {
        goto cleanup;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        goto cleanup;
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        goto cleanup;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        goto cleanup;
    }

    if (EVP_DigestSignUpdate
        (md_ctx, string_to_sign, flb_sds_len(string_to_sign)) <= 0) {
        goto cleanup;
    }

    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0) {
        goto cleanup;
    }

    signature = flb_malloc(sig_len);
    if (!signature) {
        goto cleanup;
    }

    if (EVP_DigestSignFinal(md_ctx, signature, &sig_len) <= 0) {
        goto cleanup;
    }

    size_t b64_size = ((sig_len + 2) / 3) * 4 + 1;
    size_t olen = 0;
    b64_out = flb_malloc(b64_size);

    if (!b64_out) {
        goto cleanup;
    }

    if (flb_base64_encode(b64_out, b64_size, &olen, signature, sig_len) != 0) {
        goto cleanup;
    }

    b64_out[olen] = '\0';

    auth_header = flb_sds_create_size(2048);
    if (!auth_header) {
        goto cleanup;
    }

    flb_sds_printf(&auth_header,
                   "Signature version=\"1\",keyId=\"%s/fed-x509/%s\",algorithm=\"rsa-sha256\","
                   "signature=\"%s\",headers=\"date (request-target) content-length content-type x-content-sha256\"",
                   ctx->imds.tenancy_ocid, ctx->imds.fingerprint, b64_out);

  cleanup:
    if (bio) {
        BIO_free(bio);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (signature) {
        flb_free(signature);
    }
    if (b64_out) {
        flb_free(b64_out);
    }
    if (string_to_sign) {
        flb_sds_destroy(string_to_sign);
    }
    if (lowercase_method) {
        flb_sds_destroy(lowercase_method);
    }
    flb_plg_debug(ctx->ins, "auth header: %s", auth_header);

    return auth_header;
}

static flb_sds_t clean_token_string(flb_sds_t input)
{
    if (!input)
        return NULL;

    size_t len = flb_sds_len(input);
    size_t write_pos = 0;

    for (size_t read_pos = 0; read_pos < len; read_pos++) {
        char c = input[read_pos];
        if (c >= 32 && c <= 126) {
            input[write_pos++] = c;
        }
    }

    input[write_pos] = '\0';
    flb_sds_len_set(input, write_pos);

    return input;
}


static int parse_federation_response(flb_sds_t response,
                                     struct oci_security_token *token)
{
    cJSON *json = NULL;
    cJSON *token_item = NULL;

    if (!response || !token) {
        return -1;
    }

    json = cJSON_Parse(response);
    if (!json) {
        return -1;
    }

    token_item = cJSON_GetObjectItem(json, "token");
    if (!token_item || !cJSON_IsString(token_item)) {
        cJSON_Delete(json);
        return -1;
    }

    const char *token_str = cJSON_GetStringValue(token_item);
    if (!token_str) {
        cJSON_Delete(json);
        return -1;
    }

    flb_sds_t raw_token = flb_sds_create(token_str);    // should be freed later
    if (!raw_token) {
        cJSON_Delete(json);
        return -1;
    }

    if (!clean_token_string(raw_token)) {
        flb_sds_destroy(raw_token);
        cJSON_Delete(json);
        return -1;
    }

    if (token) {
        flb_sds_destroy(token->token);
    }
    token->token = raw_token;

    cJSON_Delete(json);
    return 0;
}

static int decode_jwt_and_set_expires(struct flb_oci_logan *ctx)
{
    if (!ctx || !ctx->security_token.token) {
        flb_plg_error(ctx->ins, "Invalid context or token");
        return -1;
    }

    char *token = ctx->security_token.token;
    char *dot1 = strchr(token, '.');
    char *dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;

    if (!dot1 || !dot2) {
        flb_plg_error(ctx->ins, "Invalid JWT format");
        return -1;
    }

    size_t payload_b64url_len = dot2 - (dot1 + 1);
    char *payload_b64url = flb_malloc(payload_b64url_len + 1);
    if (!payload_b64url) {
        return -1;
    }

    memcpy(payload_b64url, dot1 + 1, payload_b64url_len);
    payload_b64url[payload_b64url_len] = '\0';

    for (int i = 0; i < payload_b64url_len; i++) {
        if (payload_b64url[i] == '-')
            payload_b64url[i] = '+';
        else if (payload_b64url[i] == '_')
            payload_b64url[i] = '/';
    }

    int padding = (4 - (payload_b64url_len % 4)) % 4;
    size_t b64_len = payload_b64url_len + padding;
    char *payload_b64 = flb_malloc(b64_len + 1);
    if (!payload_b64) {
        flb_free(payload_b64url);
        return -1;
    }

    strncpy(payload_b64, payload_b64url, payload_b64url_len);
    memset(payload_b64 + payload_b64url_len, '=', padding);
    payload_b64[b64_len] = '\0';

    size_t decoded_len = (b64_len * 3) / 4 + 1;
    char *decoded_payload = flb_malloc(decoded_len);
    if (!decoded_payload) {
        flb_free(payload_b64url);
        flb_free(payload_b64);
        return -1;
    }

    int ret =
        flb_base64_decode((unsigned char *) decoded_payload, decoded_len,
                          &decoded_len, (unsigned char *) payload_b64,
                          b64_len);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "Base64 decode failed");
        flb_free(payload_b64url);
        flb_free(payload_b64);
        flb_free(decoded_payload);
        return -1;
    }

    decoded_payload[decoded_len] = '\0';
    flb_plg_debug(ctx->ins, "decoded payload -> [%s]", decoded_payload);
    // there was a hbo
    cJSON *json = cJSON_Parse(decoded_payload);
    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            flb_plg_error(ctx->ins, "JSON parse error before: %s", error_ptr);
        }
        else {
            flb_plg_error(ctx->ins, "JSON parse error");
        }
        flb_free(payload_b64url);
        flb_free(payload_b64);
        flb_free(decoded_payload);
        return -1;
    }

    cJSON *exp_item = cJSON_GetObjectItem(json, "exp");
    if (!exp_item || !cJSON_IsNumber(exp_item)) {
        flb_plg_error(ctx->ins, "Missing or invalid 'exp' in JWT");
        cJSON_Delete(json);
        flb_free(payload_b64url);
        flb_free(payload_b64);
        flb_free(decoded_payload);
        return -1;
    }

    time_t exp_value = (time_t) exp_item->valuedouble;
    flb_plg_debug(ctx->ins, "Found exp value: %ld", (long) exp_value);
    char *json_str = cJSON_Print(json);
    if (json_str) {
        flb_free(json_str);
    }

    ctx->security_token.expires_at = exp_value;

    cJSON_Delete(json);
    flb_free(payload_b64url);
    flb_free(payload_b64);
    flb_free(decoded_payload);

    return 0;
}

flb_sds_t sign_and_send_federation_request(struct flb_oci_logan *ctx,
                                           flb_sds_t payload)
{
    struct flb_upstream *upstream;
    struct flb_http_client *client;
    size_t b_sent;
    int ret;
    struct flb_connection *u_conn;
    flb_sds_t resp = NULL;
    int port = 443;
    flb_sds_t url_path = flb_sds_create("/v1/x509");
    flb_sds_t auth_header = NULL;
    flb_sds_t date_header = NULL;
    flb_plg_debug(ctx->ins, "ctx->imds->region -> %s", ctx->imds.region);
    // char *host = flb_calloc(100, 1);
    // sprintf(host, "auth.%s.oraclecloud.com", ctx->imds.region);
    flb_sds_t tmp_host = construct_oci_host("auth", ctx->imds.region);
    char *host = flb_calloc(flb_sds_len(tmp_host) + 1, 1);
    time_t now;
    struct tm *tm_info;
    char date_buf[128];

    strcpy(host, tmp_host);
    flb_sds_destroy(tmp_host);
    flb_plg_debug(ctx->ins, "host -> %s", host);
    time(&now);
    tm_info = gmtime(&now);
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT",
             tm_info);
    date_header = flb_sds_create(date_buf);

    if (!date_header) {
        flb_free(host);
        flb_sds_destroy(url_path);
        return NULL;
    }

    upstream = flb_upstream_create(ctx->ins->config, host, port,
                                   FLB_IO_TLS, ctx->ins->tls);
    if (!upstream) {
        flb_free(host);
        flb_sds_destroy(url_path);
        return NULL;
    }

    u_conn = flb_upstream_conn_get(upstream);
    if (!u_conn) {
        flb_upstream_destroy(upstream);
        flb_free(host);
        flb_sds_destroy(url_path);
        return NULL;
    }
    client = flb_http_client(u_conn, FLB_HTTP_POST, url_path,
                             payload, strlen(payload), host, port, NULL, 0);

    if (!client) {
        flb_upstream_conn_release(u_conn);
        flb_upstream_destroy(upstream);
        flb_free(host);
        flb_sds_destroy(url_path);
        flb_sds_destroy(date_header);
        return NULL;
    }

    char user_agent[256];
    snprintf(user_agent, sizeof(user_agent),
             "fluent-bit-oci-plugin/%s", ctx->ins->p->name);
    flb_http_add_header(client, "Date", 4, date_header,
                        flb_sds_len(date_header));
    flb_http_add_header(client, "Content-Type", 12, "application/json", 16);
    flb_http_add_header(client, "Content-Length", 14, NULL, 0);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char *b64_hash = NULL;
    size_t b64_len = 0;

    SHA256((unsigned char *) payload, flb_sds_len(payload), hash);

    b64_len = 4 * ((SHA256_DIGEST_LENGTH + 2) / 3) + 1;
    b64_hash = flb_malloc(b64_len);
    if (!b64_hash) {
        goto cleanup;
    }
    if (flb_base64_encode
        ((unsigned char *) b64_hash, b64_len, &b64_len, hash,
         SHA256_DIGEST_LENGTH) != 0) {
        flb_free(b64_hash);
        goto cleanup;
    }
    b64_hash[b64_len] = '\0';
    flb_http_add_header(client, "x-content-sha256", 16, b64_hash, b64_len);
    flb_http_add_header(client, "User-Agent", 10, user_agent,
                        strlen(user_agent));
    // sign request using the leaf key
    flb_plg_debug(ctx->ins, "signing with tenancy: %s, fingerprint: %s",
                  ctx->imds.tenancy_ocid, ctx->imds.fingerprint);
    auth_header = sign_request_with_key(ctx, "POST", url_path,
                                        payload, date_header, host);
    if (auth_header) {
        flb_http_add_header(client, "Authorization", 13,
                            auth_header, flb_sds_len(auth_header));
    }
    ret = flb_http_do(client, &b_sent);

    if (ret != 0 || client->resp.status != 200) {
        flb_plg_error(ctx->ins,
                      "federation request failed with status %d: %s",
                      client->resp.status, client->resp.payload);
        flb_plg_error(ctx->ins, "authentication failed with status %d",
                      client->resp.status);

        flb_plg_debug(ctx->ins, "request headers:");
        flb_plg_debug(ctx->ins, "  Authorization: %s", auth_header);
        flb_plg_debug(ctx->ins, "  Date: %s", date_header);
        flb_plg_debug(ctx->ins, "  Content-Type: application/json");
        flb_plg_debug(ctx->ins, "  x-content-sha256: %s", b64_hash);
        flb_plg_debug(ctx->ins, "request body: %s", payload);
        goto cleanup;
    }

    flb_plg_debug(ctx->ins, "status_code -> %d\nurl -> %s\n header -> %s",
                  client->resp.status, client->uri, client->resp.data);
    resp =
        flb_sds_create_len(client->resp.payload, client->resp.payload_size);
    flb_plg_debug(ctx->ins, "resp->%s", resp);
    if (parse_federation_response(resp, &ctx->security_token) < 0) {
        flb_plg_error(ctx->ins, "failed to parse federation response");
        return NULL;
    }
    flb_plg_debug(ctx->ins, "ctx->security_token-> %s",
                  ctx->security_token.token);

    if (client->resp.payload && client->resp.payload_size > 0) {
        resp =
            flb_sds_create_len(client->resp.payload,
                               client->resp.payload_size);

        if (parse_federation_response(resp, &ctx->security_token) < 0) {
            flb_plg_error(ctx->ins, "failed to parse federation response");
            flb_sds_destroy(resp);
            resp = NULL;
            flb_free(b64_hash);
            goto cleanup;
        }

        decode_jwt_and_set_expires(ctx);
    }
  cleanup:
    if (auth_header) {
        flb_sds_destroy(auth_header);
    }
    flb_sds_destroy(date_header);
    flb_sds_destroy(url_path);
    flb_free(host);
    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);
    flb_upstream_destroy(upstream);

    return resp;
}

struct flb_oci_logan *flb_oci_logan_conf_create(struct flb_output_instance
                                                *ins,
                                                struct flb_config *config)
{
    struct flb_oci_logan *ctx;
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    int ret = 0;
    char *protocol = NULL;
    char *p_host = NULL;
    char *p_port = NULL;
    char *p_uri = NULL;

    ctx = flb_calloc(1, sizeof(struct flb_oci_logan));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&ctx->global_metadata_fields);
    mk_list_init(&ctx->log_event_metadata_fields);

    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }

    if (strcmp(ctx->auth_mode, "instance_principal") == 0) {
        flb_plg_info(ctx->ins, "Using instance principal authentication");

        if (get_keys_and_certs(ctx, config) != 1) {
            flb_plg_error(ctx->ins, "get_keys_and_certs_failed");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ctx->session_key_pair = generate_session_key_pair(ctx);
        if (!ctx->session_key_pair) {
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ctx->imds.session_pubkey = extract_public_key_pem(ctx->session_key_pair);       // should be freed later
        ctx->imds.session_privkey = extract_private_key_pem(ctx->session_key_pair);     // should be freed later

        if (!ctx->imds.session_pubkey || !ctx->imds.session_privkey) {
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        flb_sds_t json_payload = create_federation_payload(ctx);        // should be freed later
        if (!json_payload) {
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        flb_sds_t response = sign_and_send_federation_request(ctx, json_payload);       // should be freed later
        flb_sds_destroy(json_payload);

        if (!response) {
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        flb_plg_debug(ctx->ins, "federation token -> %s",
                      ctx->security_token.token);
        flb_sds_destroy(response);

        if (ctx->imds.region) {
            ctx->region = flb_sds_create(ctx->imds.region);
        }
        // still not fixed
    }
    else {
        if (!ctx->config_file_location) {
            flb_plg_error(ctx->ins,
                          "config file location i's required for config_file auth mode");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ret = load_oci_credentials(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        if (create_pk_context(ctx->key_file, NULL, ctx) < 0) {
            flb_plg_error(ctx->ins, "failed to create pk context");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ctx->key_id = flb_sds_create_size(512);
        flb_sds_snprintf(&ctx->key_id, flb_sds_alloc(ctx->key_id),
                         "%s/%s/%s", ctx->tenancy, ctx->user,
                         ctx->key_fingerprint);
    }

    if (ctx->oci_config_in_record == FLB_FALSE) {
        if (ctx->oci_la_log_source_name == NULL ||
            ctx->oci_la_log_group_id == NULL) {
            flb_plg_error(ctx->ins,
                          "log source name and log group id are required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->oci_la_global_metadata != NULL) {
        ret = global_metadata_fields_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->oci_la_metadata != NULL) {
        ret = log_event_metadata_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    // Setup host and URI
    if (ins->host.name) {
        host = ins->host.name;
    }
    else {
        if (!ctx->region) {
            flb_plg_error(ctx->ins, "Region is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        // host = flb_sds_create_size(512);
        // flb_sds_snprintf(&host, flb_sds_alloc(host), "loganalytics.%s.oci.oraclecloud.com", ctx->region);
        host = construct_oci_host("loganalytics", ctx->region); // should be freed later
    }
    flb_plg_debug(ctx->ins, "host -> %s", host);
    if (!ctx->uri) {
        if (!ctx->namespace) {
            flb_plg_error(ctx->ins, "Namespace is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        ctx->uri = flb_sds_create_size(512);
        flb_sds_snprintf(&ctx->uri, flb_sds_alloc(ctx->uri),
                         "/20200601/namespaces/%s/actions/uploadLogEventsFile",
                         ctx->namespace);
    }

    /* Check if SSL/TLS is enabled */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        default_port = 443;
    }
    else {
        flb_plg_error(ctx->ins, "TLS must be enabled for OCI");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }
#else
    flb_plg_error(ctx->ins, "TLS support required for OCI");
    flb_oci_logan_conf_destroy(ctx);
    return NULL;
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    flb_output_net_default(host, default_port, ins);

    if (!ins->host.name) {
        flb_sds_destroy(host);
    }

    // Setup proxy if configured
    if (ctx->proxy) {
        ret =
            flb_utils_url_split(ctx->proxy, &protocol, &p_host, &p_port,
                                &p_uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'",
                          ctx->proxy);
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ctx->proxy_host = p_host;
        ctx->proxy_port = atoi(p_port);
        flb_free(protocol);
        flb_free(p_port);
        flb_free(p_uri);
    }

    // Create upstream connection
    if (ctx->proxy) {
        upstream =
            flb_upstream_create(config, ctx->proxy_host, ctx->proxy_port,
                                io_flags, ins->tls);
    }
    else {
        upstream = flb_upstream_create(config, ins->host.name, ins->host.port,
                                       io_flags, ins->tls);
    }

    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create upstream context");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }
    ctx->u = upstream;

    flb_output_upstream_set(ctx->u, ins);

    return ctx;
}

static void metadata_fields_destroy(struct flb_oci_logan *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct metadata_obj *f;

    mk_list_foreach_safe(head, tmp, &ctx->global_metadata_fields) {
        f = mk_list_entry(head, struct metadata_obj, _head);
        if (f->key) {
            flb_sds_destroy(f->key);
        }
        if (f->val) {
            flb_sds_destroy(f->val);
        }
        mk_list_del(&f->_head);
        flb_free(f);
    }

    mk_list_foreach_safe(head, tmp, &ctx->log_event_metadata_fields) {
        f = mk_list_entry(head, struct metadata_obj, _head);
        if (f->key) {
            flb_sds_destroy(f->key);
        }
        if (f->val) {
            flb_sds_destroy(f->val);
        }
        mk_list_del(&f->_head);
        flb_free(f);
    }

}

int flb_oci_logan_conf_destroy(struct flb_oci_logan *ctx)
{
    if (ctx == NULL) {
        return 0;
    }

    if (ctx->private_key) {
        flb_sds_destroy(ctx->private_key);
    }
    if (ctx->uri) {
        flb_sds_destroy(ctx->uri);
    }
    if (ctx->key_id) {
        flb_sds_destroy(ctx->key_id);
    }
    if (ctx->key_file) {
        flb_sds_destroy(ctx->key_file);
    }
    if (ctx->user) {
        flb_sds_destroy(ctx->user);
    }
    if (ctx->key_fingerprint) {
        flb_sds_destroy(ctx->key_fingerprint);
    }
    if (ctx->tenancy) {
        flb_sds_destroy(ctx->tenancy);
    }
    if (ctx->region) {
        flb_sds_destroy(ctx->region);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    metadata_fields_destroy(ctx);

    flb_free(ctx);
    return 0;
}
