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
    char* key = NULL;
    char* val;

    content = flb_file_read(ctx->config_file_location);
    if (content == NULL || flb_sds_len(content) == 0)
    {
        return -1;
    }
    flb_plg_debug(ctx->ins, "content = %s", content);
    line = strtok(content, "\n");
    while(line != NULL) {
        /* process line */
        flb_plg_debug(ctx->ins, "line = %s", line);
        if(!found_profile && line[0] == '[') {
            profile = mk_string_copy_substr(line, 1, strlen(line) - 1);
            if(!strcmp(profile, ctx->profile_name)) {
                flb_plg_info(ctx->ins, "found profile");
                found_profile = 1;
                goto iterate;
            }
            mk_mem_free(profile);
            profile = NULL;
        }
        if(found_profile) {
            if(line[0] == '[') {
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
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
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
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
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

static flb_sds_t make_imds_request(struct flb_oci_logan *ctx, struct flb_connection *u_conn, const char *path)
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

char *extract_region(const char *response) {
    const char *body_start = strstr(response, "\r\n\r\n");
    if (!body_start) {
        return NULL;
    }

    body_start += 4;

    while (*body_start == '\n' || *body_start == '\r' || *body_start == ' ') {
        body_start++;
    }

    size_t len = strlen(body_start);
    while (len > 0 && (body_start[len - 1] == '\n' || body_start[len - 1] == '\r' || body_start[len - 1] == ' ')) {
        len--;
    }

    char *region = malloc(len + 1);
    if (!region) {
        return NULL;
    }

    strncpy(region, body_start, len);
    region[len] = '\0';
    // still have to convert it to long name
    return region;
}

char *extract_pem_content(const char *response, const char *begin_marker, const char *end_marker)
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
    char *pem_content = malloc(pem_length + 1);
    if (!pem_content) {
        return NULL;
    }

    strncpy(pem_content, start, pem_length);
    pem_content[pem_length] = '\0';

    return pem_content;
}

flb_sds_t calculate_certificate_fingerprint(struct flb_oci_logan *ctx, const char *cert_pem)
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
        *(p-1) = '\0';
    }
    
    fingerprint = flb_sds_create(hex_fingerprint);

    for (int i = 0; i< flb_sds_len(fingerprint);i++){
        if (islower(fingerprint[i])) {
            fingerprint[i] = toupper(fingerprint[i]);
        }

    }
    X509_free(cert);
    BIO_free(bio);
    
    return fingerprint;
}

bool extract_tenancy_compartment_ocid(struct flb_oci_logan *ctx, const char *cert_pem)
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
    flb_sds_t compartment_ocid = NULL;
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
            const char *ou_str = (const char *)ASN1_STRING_get0_data(data);

            if (strstr(ou_str, "opc-tenant:ocid1.tenancy") == ou_str) {
                const char *ocid = strchr(ou_str, ':');
                if (ocid && strlen(ocid + 1) > 0) {
                    tenancy_ocid = flb_sds_create(ocid + 1);
                    if(compartment_ocid)
                        break;
                }
            }
            else if(strstr(ou_str, "opc-compartment:ocid1.compartment") == ou_str){
                const char *ocid = strchr(ou_str, ':');
                if (ocid && strlen(ocid + 1) > 0) {
                    compartment_ocid = flb_sds_create(ocid + 1);
                    if(tenancy_ocid)
                        break;
                }
            }
        }
    }
    // BIO *out = BIO_new(BIO_s_mem());
    // if (!out) {
    //     flb_plg_error(ctx->ins, "failed to create BIO for printing certificate");
    //     X509_free(cert);
    //     return 0;
    // }

    // //just for debugging should be removed after
    // X509_print(out, cert);

    // char *cert_info = NULL;
    // long len = BIO_get_mem_data(out, &cert_info);
    // char *copy = malloc(len + 1);
    // if (copy) {
    //     memcpy(copy, cert_info, len);
    //     copy[len] = '\0';
    //     flb_plg_debug(ctx->ins, "full cert:\n%s", copy);
    //     flb_plg_debug(ctx->ins, "eof cert");
    //     free(copy);
    // }

    // BIO_free(out);

    X509_free(cert);

    if (!tenancy_ocid || !compartment_ocid) {
        return 0;
    }

    ctx->imds.compartment_ocid = compartment_ocid;
    ctx->imds.tenancy_ocid = tenancy_ocid;
    return 1;
}

int get_keys_and_certs(struct flb_oci_logan *ctx, struct flb_config *config)
{
    ctx->u = flb_upstream_create(config, ORACLE_IMDS_HOST, 80, FLB_IO_TCP, NULL);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "failed to create upstream");
        return 0;
    }

    struct flb_connection *u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "failed to get upstream connection");
        return 0;
    }
    flb_sds_t region_resp = make_imds_request(ctx, u_conn, ORACLE_IMDS_BASE_URL ORACLE_IMDS_REGION_PATH);
    flb_sds_t cert_resp = make_imds_request(ctx, u_conn, ORACLE_IMDS_BASE_URL ORACLE_IMDS_LEAF_CERT_PATH);
    flb_sds_t key_resp = make_imds_request(ctx, u_conn, ORACLE_IMDS_BASE_URL ORACLE_IMDS_LEAF_KEY_PATH);
    flb_sds_t int_cert_resp = make_imds_request(ctx, u_conn, ORACLE_IMDS_BASE_URL ORACLE_IMDS_INTERMEDIATE_CERT_PATH);

    if (!region_resp) {
        flb_plg_error(ctx->ins, "failed to get region from IMDS");
        goto error;
    }
    char *clean_region_resp = extract_region(region_resp);

    if (!cert_resp) {
        flb_plg_error(ctx->ins, "failed to get leaf cert from IMDS");
        goto error;
    }
    // still to be freed
    char *clean_cert_resp = extract_pem_content(cert_resp, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
    if (!key_resp) {
        goto error;
    }
    char *clean_private_key = extract_pem_content(key_resp, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");

    if (!int_cert_resp) {
        goto error;    
    }
    char *clean_int_cert = extract_pem_content(int_cert_resp, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
    ctx->imds.region = clean_region_resp;
    ctx->imds.region = "us-phoenix-1";
    ctx->imds.leaf_cert = clean_cert_resp;
    ctx->imds.intermediate_cert = int_cert_resp;
    char *pem_start = strstr(key_resp, "-----BEGIN");
    char *pem_end = strstr(key_resp, "-----END");
    if (!pem_start || !pem_end) {
        flb_plg_error(ctx->ins, "No valid PEM block found");
        return -1;
    }
    size_t pem_len = (pem_end - pem_start) + strlen("-----END RSA PRIVATE KEY-----") + 1;
    ctx->imds.leaf_key = flb_sds_create_len(pem_start, pem_len);

    if (!extract_tenancy_compartment_ocid(ctx, clean_cert_resp)) {
        goto error;
    }
    ctx->imds.fingerprint = calculate_certificate_fingerprint(ctx, clean_cert_resp);
    if(!ctx->imds.fingerprint){
        goto error;
    }
    ctx->imds.federation_endpoint = flb_sds_create_size(128);
    // just temporary should be removed and replaced with something like mapping in python3 sdk
    flb_sds_printf(&ctx->imds.federation_endpoint, "https://auth.%s.oraclecloud.com/v1/x509", 
                  flb_sds_create("us-phoenix-1"));
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
    return 0;
}

static EVP_PKEY *generate_session_key_pair(struct flb_oci_logan *ctx)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    BIGNUM *bn = BN_new();
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


char *extract_public_key_pem(EVP_PKEY *pkey) {
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

char *extract_private_key_pem(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return NULL; 
    }
    
    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, NULL, NULL, NULL)) {
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

static flb_sds_t sanitize_certificate(const char *cert_str) {
    if (!cert_str) return NULL;
    
    const char *start = strstr(cert_str, "-----BEGIN");
    if (!start) return NULL;
    
    start = strchr(start, '\n');
    if (!start) return NULL;
    start++;
    
    const char *end = strstr(cert_str, "-----END");
    if (!end || end <= start) return NULL;
    
    flb_sds_t clean = flb_sds_create_len(start, end - start);
    if (!clean) return NULL;
    
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

static flb_sds_t create_federation_payload(struct flb_oci_logan *ctx)
{
    flb_sds_t payload = NULL;
    flb_sds_t leaf_cert = sanitize_certificate(ctx->imds.leaf_cert);
    flb_sds_t session_pubkey = sanitize_certificate(ctx->imds.session_pubkey);
    flb_sds_t intermediate_certs = sanitize_certificate(ctx->imds.intermediate_cert);

    if (ctx->imds.intermediate_cert) {
        intermediate_certs = sanitize_certificate(ctx->imds.intermediate_cert);
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




struct flb_oci_logan *flb_oci_logan_conf_create(struct flb_output_instance *ins,
                                                struct flb_config *config) {
    struct flb_oci_logan *ctx;
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    const char *tmp;
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

    if(strcmp(ctx->auth_mode, "instance_principal") == 0){
        flb_plg_info(ctx->ins, "Using instance principal authentication");
        
        if (get_keys_and_certs(ctx, config) != 1) {
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        
        ctx->session_key_pair = generate_session_key_pair(ctx);
        if (!ctx->session_key_pair) {
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        
        ctx->imds.session_pubkey = extract_public_key_pem(ctx->session_key_pair);
        ctx->imds.session_privkey = extract_private_key_pem(ctx->session_key_pair);
        
        if (!ctx->imds.session_pubkey || !ctx->imds.session_privkey) {
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        
        flb_sds_t json_payload = create_federation_payload(ctx);
        if (!json_payload) {
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        
        flb_plg_debug(ctx->ins, "json_payload -> %s", json_payload);
    } else {
        if (!ctx->config_file_location) {
            flb_plg_error(ctx->ins, "config file location i's required for config_file auth mode");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ret = load_oci_credentials(ctx);
        if(ret != 0) {
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
                         "%s/%s/%s", ctx->tenancy, ctx->user, ctx->key_fingerprint);
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
        host = flb_sds_create_size(512);
        flb_sds_snprintf(&host, flb_sds_alloc(host), "loganalytics.%s.oci.oraclecloud.com", ctx->region);
    }

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
        ret = flb_utils_url_split(ctx->proxy, &protocol, &p_host, &p_port, &p_uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", ctx->proxy);
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
        upstream = flb_upstream_create(config, ctx->proxy_host, ctx->proxy_port,
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

int flb_oci_logan_conf_destroy(struct flb_oci_logan *ctx) {
    if(ctx == NULL) {
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
    if(ctx->user) {
        flb_sds_destroy(ctx->user);
    }
    if(ctx->key_fingerprint) {
        flb_sds_destroy(ctx->key_fingerprint);
    }
    if(ctx->tenancy) {
        flb_sds_destroy(ctx->tenancy);
    }
    if(ctx->region) {
        flb_sds_destroy(ctx->region);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    metadata_fields_destroy(ctx);

    flb_free(ctx);
    return 0;
}
