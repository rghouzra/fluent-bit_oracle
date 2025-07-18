# Oracle Cloud Infrastructure (OCI) Log Analytics Plugin for Fluent Bit

This plugin allows Fluent Bit to send logs to Oracle Cloud Infrastructure Log analytics service.

## Requirements

### System Requirements
- Fluent Bit with TLS support enabled
- OpenSSL libraries for cryptographic operations
- Network access to OCI Log Analytics endpoints
- cJSON (for instance principal authentication)
### OCI Requirements
- OCI tenancy with Log Analytics service enabled
- Log Analytics namespace configured
- Log group and log source configured in OCI Log Analytics
- Appropriate IAM policies for authentication method chosen

## Authentication Methods

The plugin supports two authentication methods:

### 1. Config File Authentication (API Key)
use OCI configuration file with API key pairs.

### 2. Instance Principal Authentication
use instance principal authentication for OCI compute instances (no API keys required).

## Setup Instructions

### Option 1: Config File Authentication

#### Step 1: Create OCI Config File

Create `~/.oci/config`:

```conf
[DEFAULT]
user=ocid1.user.oc1..aaaaaaaa...
fingerprint=12:34:56:78:9a:bc:de:f0:12:34:56:78:9a:bc:de:f0
key_file=~/.oci/oci_api_key.pem #path to your privkey
tenancy=ocid1.tenancy.oc1..aaaaaaaa...
region=us-ashburn-1
```

#### Step 2: Fluent Bit Configuration

```conf
[OUTPUT]
    Name oracle_log_analytics
    Match *
    auth_mode config_file
    config_file_location ~/.oci/config
    profile_name DEFAULT
    namespace your_namespace_name
    oci_la_log_group_id ocid1.loggroup.oc1..aaaaaaaa...
    oci_la_log_source_name "Custom Log Source"
    tls On
```

### Option 2: Instance Principal Authentication

#### Step 1: Fluent Bit Configuration

```conf
[OUTPUT]
    Name oracle_log_analytics
    Match *
    auth_mode instance_principal
    namespace your_namespace
    oci_la_log_group_id ocid1.loggroup.oc1..aaaaaaaa...
    oci_la_log_source_name "Instance Log Source"
    tls On
```