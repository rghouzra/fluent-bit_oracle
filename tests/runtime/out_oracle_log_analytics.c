
#include <fluent-bit.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_stream.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include "flb_tests_runtime.h"
#include <stdlib.h>
#include <unistd.h>



//either i use an input pluging and compare batches with the buffer, or we use like a hash

void test_instance_principal_auth()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *input = "[0, {\"message\":\"test log message\"}]";

    // setenv("FLB_OCI_PLUGIN_UNDER_TEST", "1", 1);
    setenv("TEST_IMDS_SUCCESS", "1", 1);
    
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", "log_level", "debug", NULL);

    in_ffd = flb_input(ctx, "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, "oracle_log_analytics", NULL);
    TEST_CHECK(out_ffd >= 0);
    
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "auth_type", "instance_principal",
                   "namespace", "test_namespace",
                   "oci_la_log_group_id", "test_log_group",
                   "oci_la_log_source_name", "test_source",
                   "tls", "on",
                   "tls.verify", "off",
                   NULL);

    ret = flb_start(ctx);
    if (ret == 0) {
        flb_lib_push(ctx, in_ffd, input, strlen(input));
        sleep(2);
        flb_stop(ctx);
    }

    flb_destroy(ctx);
    
    unsetenv("FLB_OCI_PLUGIN_UNDER_TEST");
    unsetenv("TEST_IMDS_SUCCESS");
    
}

void test_imds_failure()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    

    setenv("FLB_OCI_PLUGIN_UNDER_TEST", "1", 1);
    setenv("TEST_IMDS_FAILURE", "1", 1);
    
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", "log_level", "debug", NULL);

    
    in_ffd = flb_input(ctx, "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    
    out_ffd = flb_output(ctx, "oracle_log_analytics", NULL);
    TEST_CHECK(out_ffd >= 0);
    
    
    flb_output_set(ctx, out_ffd,
                   "match", "test", 
                   "auth_type", "instance_principal",
                   "namespace", "test_namespace",
                   "oci_la_log_group_id", "test_log_group",
                   "oci_la_log_source_name", "test_source",
                   NULL);

    
    ret = flb_start(ctx);
    
    TEST_CHECK(ret != 0);

    
    flb_destroy(ctx);
    
    
    unsetenv("FLB_OCI_PLUGIN_UNDER_TEST");
    unsetenv("TEST_IMDS_FAILURE");
    
}


void test_config_file_auth()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char config_content[] = 
        "[DEFAULT]\n"
        "user=ocid1.user.oc1..test\n"
        "fingerprint=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff\n"
        "tenancy=ocid1.tenancy.oc1..test\n"
        "region=us-ashburn-1\n"
        "key_file=/tmp/test_key.pem\n";
    
    char key_content[] = 
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAtest_key_content_here\n"
        "-----END RSA PRIVATE KEY-----\n";
    

    
    FILE *config_file = fopen("/tmp/test_oci_config", "w");
    if (config_file) {
        fwrite(config_content, 1, strlen(config_content), config_file);
        fclose(config_file);
    }
    
    FILE *key_file = fopen("/tmp/test_key.pem", "w");
    if (key_file) {
        fwrite(key_content, 1, strlen(key_content), key_file);
        fclose(key_file);
    }

    
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", "log_level", "debug", NULL);

    
    in_ffd = flb_input(ctx, "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    
    out_ffd = flb_output(ctx, "oracle_log_analytics", NULL);
    TEST_CHECK(out_ffd >= 0);
    
    
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "auth_type", "config_file",
                   "config_file_location", "/tmp/test_oci_config",
                   "namespace", "test_namespace", 
                   "oci_la_log_group_id", "test_log_group",
                   "oci_la_log_source_name", "test_source",
                   "tls", "on",
                   "tls.verify", "off",
                   NULL);

    
    ret = flb_start(ctx);
    

    
    flb_destroy(ctx);
    
    
    unlink("/tmp/test_oci_config");
    unlink("/tmp/test_key.pem");
    
}

TEST_LIST = {
    {"test_instance_principal_auth", test_instance_principal_auth},
    {"test_imds_failure", test_imds_failure}, 
    {"test_config_file_auth", test_config_file_auth},
    {0}
};

