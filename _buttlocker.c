#ifndef BUTTLOCKER_C_
#define BUTTLOCKER_C_

#include "_sha256.c"
#include "_charm.c"

// ------------------------------------------------------------------


#if defined(__x86_64__) || defined(__x86_64)
static inline __attribute__((always_inline))
uint64_t rdrand64(void)
{
        uint64_t        ret;
        asm volatile("1:;\n\
        rdrand %0;\n\
        jnc 1b;\n":"=r"(ret));
        return ret;
}

static inline __attribute__((always_inline,nonnull))
void random_nonce(uint8_t (*out)[SHA256_SIZE_BYTES])
{
    unsigned i;
    uint64_t *out64 = (uint64_t*)out;
    for( i = 0; i < (SHA256_SIZE_BYTES/sizeof(uint64_t)); i++ ) {
        out64[i] = rdrand64();
    }
}
#else
# error "TODO: unimplemented on non-x86_64"
#endif


// ------------------------------------------------------------------
// https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/TrEEProtocol.h
// https://learn.microsoft.com/en-us/windows-hardware/test/hlk/testref/trusted-execution-environment-efi-protocol
// https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/


#define EFI_TREE_PROTOCOL_GUID {0x607f766c, 0x7455, 0x42be, {0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f}}

typedef struct _EFI_TREE_PROTOCOL EFI_TREE_PROTOCOL;

typedef struct _TREE_VERSION {
  UINT8    Major;
  UINT8    Minor;
} TREE_VERSION;

typedef UINT32 TREE_EVENT_LOG_BITMAP;
typedef UINT32 TREE_EVENT_LOG_FORMAT;
typedef UINT32 TrEE_PCRINDEX;
typedef UINT32 TrEE_EVENTTYPE;

typedef struct _TREE_BOOT_SERVICE_CAPABILITY {
  UINT8                    Size;
  TREE_VERSION             StructureVersion;
  TREE_VERSION             ProtocolVersion;
  UINT32                   HashAlgorithmBitmap;
  TREE_EVENT_LOG_BITMAP    SupportedEventLogs;
  BOOLEAN                  TrEEPresentFlag;
  UINT16                   MaxCommandSize;
  UINT16                   MaxResponseSize;
  UINT32                   ManufacturerID;
} TREE_BOOT_SERVICE_CAPABILITY_1_0;

typedef TREE_BOOT_SERVICE_CAPABILITY_1_0 TREE_BOOT_SERVICE_CAPABILITY;

#define TREE_BOOT_HASH_ALG_SHA1     0x00000001
#define TREE_BOOT_HASH_ALG_SHA256   0x00000002
#define TREE_BOOT_HASH_ALG_SHA384   0x00000004
#define TREE_BOOT_HASH_ALG_SHA512   0x00000008
#define TREE_EXTEND_ONLY            0x0000000000000001
#define PE_COFF_IMAGE               0x0000000000000010
#define MAX_PCR_INDEX               23
#define TREE_EVENT_HEADER_VERSION   1

typedef struct {
  UINT32            HeaderSize;
  UINT16            HeaderVersion;
  TrEE_PCRINDEX     PCRIndex;
  TrEE_EVENTTYPE    EventType;
} __attribute__((packed)) TrEE_EVENT_HEADER;

typedef struct {
  UINT32               Size;
  TrEE_EVENT_HEADER    Header;
  UINT8                Event[1];
} __attribute__((packed)) TrEE_EVENT;

typedef
EFI_STATUS
(EFIAPI *EFI_TREE_GET_CAPABILITY)(
  IN EFI_TREE_PROTOCOL                *This,
  IN OUT TREE_BOOT_SERVICE_CAPABILITY *ProtocolCapability
  );

typedef
EFI_STATUS
(EFIAPI *EFI_TREE_GET_EVENT_LOG)(
  IN EFI_TREE_PROTOCOL     *This,
  IN TREE_EVENT_LOG_FORMAT EventLogFormat,
  OUT EFI_PHYSICAL_ADDRESS *EventLogLocation,
  OUT EFI_PHYSICAL_ADDRESS *EventLogLastEntry,
  OUT BOOLEAN              *EventLogTruncated
  );

typedef
EFI_STATUS
(EFIAPI *EFI_TREE_HASH_LOG_EXTEND_EVENT)(
  IN EFI_TREE_PROTOCOL    *This,
  IN UINT64               Flags,
  IN EFI_PHYSICAL_ADDRESS DataToHash,
  IN UINT64               DataToHashLen,
  IN TrEE_EVENT           *Event
  );

typedef
EFI_STATUS
(EFIAPI *EFI_TREE_SUBMIT_COMMAND)(
  IN EFI_TREE_PROTOCOL *This,
  IN UINT32            InputParameterBlockSize,
  IN UINT8             *InputParameterBlock,
  IN UINT32            OutputParameterBlockSize,
  IN UINT8             *OutputParameterBlock
  );

struct _EFI_TREE_PROTOCOL {
  EFI_TREE_GET_CAPABILITY           GetCapability;
  EFI_TREE_GET_EVENT_LOG            GetEventLog;
  EFI_TREE_HASH_LOG_EXTEND_EVENT    HashLogExtendEvent;
  EFI_TREE_SUBMIT_COMMAND           SubmitCommand;
}; 

#define TrEE_SubmitCommand(x, y, z) uefi_call_wrapper(in_tree->SubmitCommand, 1+4, x, sizeof(y), (UINT8 *)y, sizeof(z), (UINT8 *)z);


// ------------------------------------------------------------------
// TPM conversation to unseal a key with a PCR policy
// see: tpm-pcrpolicy-unseal-log.txt
// conversation parameters are hard-coded, makes parsing & validating easier = smaller code

typedef struct {
    uint16_t tag;
    uint32_t size;
    uint32_t code;
} __attribute__((packed)) TPM2_Header_t;

static inline __attribute__((always_inline,const))
uint16_t htons(uint16_t h)
{
    return (uint16_t)( (h << 8 & 0xFF00U) |
                       (h >> 8 & 0x00FFU) );
};

static inline __attribute__((always_inline,const))
uint32_t htonl(uint32_t h)
{
    return (uint32_t)( (h << 24 & 0xFF000000U) |
                       (h << 8  & 0x00FF0000U) |
                       (h >> 8  & 0x0000FF00U) |
                       (h >> 24 & 0x000000FFU) );
};


// ------------------------------------------------------------------


typedef struct {
    TPM2_Header_t header;
    uint32_t handles_tpmKey;
    uint32_t handles_bind;
    uint16_t nonceCaller_size;
    uint8_t nonceCaller_buffer[32];
    uint16_t encryptedSalt_size;
    uint8_t sessionType;
    uint16_t symmetric;
    uint16_t authHash;
} __attribute__((packed)) TPM2_CC_StartAuthSession_Request_t;

typedef struct {
    TPM2_Header_t header;
    uint32_t sessionHandle;
    uint32_t nonceTPM_size;
    uint8_t nonceTPM_buffer[32];
} __attribute__((packed)) TPM2_CC_StartAuthSession_Response_t;

static inline __attribute__((nonnull))
void unsealconv_StartAuthSession_request(
    TPM2_CC_StartAuthSession_Request_t *out_req,
    const uint8_t in_nonce[SHA256_SIZE_BYTES]
) {
    *out_req = (TPM2_CC_StartAuthSession_Request_t){
        {   
            htons(0x8001),           // .tag = TPM_ST.NO_SESSIONS
            htonl(sizeof(*out_req)), // .commandSize = 59 (0x3b)
            htonl(0x00000176)        // .commandCode = TPM_CC.StartAuthSession
        },
        htonl(0x40000007),           // handles.tpmKey = TPM_RH.NULL
        htonl(0x40000007),           // handles.bind = TPM_RH.NULL
        htons(SHA256_SIZE_BYTES),    // parameters.nonceCaller.size
        {0},                         // parameters.nonceCaller.buffer
        htons(0x0000),               // parameters.encryptedSalt.size = 0
        0x01,                        // parameters.sessionType = TPM_SE.POLICY
        htons(0x0010),               // parameters.symmetric.algorithm = TPM_ALG.NULL
        htons(0x000b)                // parameters.authHash = TPM_ALG.SHA256
    };
    memcpy(out_req->nonceCaller_buffer, in_nonce, SHA256_SIZE_BYTES);
}

static inline __attribute__((nonnull))
uint8_t unsealconv_StartAuthSession_response(
    const TPM2_CC_StartAuthSession_Response_t *in_resp,
    uint32_t *out_policySession,
    uint8_t (*out_nonceTPM)[SHA256_SIZE_BYTES]
) {
    uint32_t is_ok = 0xFF;
    is_ok ^= (1<<0) * (in_resp->header.size == htonl(sizeof(*in_resp)));
    is_ok ^= (1<<1) * (in_resp->header.code == 0x0);
    is_ok ^= (1<<2) * (in_resp->nonceTPM_size == htonl(SHA256_SIZE_BYTES));
    if( is_ok == 0xFF ) {
        *out_policySession = in_resp->sessionHandle;
        memcpy(out_nonceTPM, in_resp->nonceTPM_buffer, SHA256_SIZE_BYTES);
        return 0;
    }
    return is_ok;
}

static inline __attribute__((nonnull))
const CHAR16* unsealconv_StartAuthSession(
    EFI_TREE_PROTOCOL *in_tree,
    uint32_t *out_policySession,
    uint8_t (*out_nonceTPM)[SHA256_SIZE_BYTES])
{
    uint8_t ps_nonce[SHA256_SIZE_BYTES];
    random_nonce(&ps_nonce);

    TPM2_CC_StartAuthSession_Request_t ps_req;
    unsealconv_StartAuthSession_request(&ps_req, ps_nonce);

    TPM2_CC_StartAuthSession_Response_t ps_resp;
    EFI_STATUS err = TrEE_SubmitCommand(in_tree, &ps_req, &ps_resp);
    if( EFI_ERROR(err) ) {
        return L"E" LINE_AS_STR;
    }

    if( unsealconv_StartAuthSession_response(&ps_resp, out_policySession, out_nonceTPM) ) {
        return L"E" LINE_AS_STR;
    }

    return NULL;
}


// ------------------------------------------------------------------


typedef struct {
    TPM2_Header_t header;
    uint32_t objectHandle;
} __attribute__((packed)) TPM2_CC_ReadPublic_Request_t;

typedef struct {
    TPM2_Header_t header;
    struct {
        uint16_t size;
        struct {
            uint16_t type;
            uint16_t nameAlg;
            uint32_t objectAttributes;
            struct {                
                uint32_t size;
                uint8_t  buffer[32];
            } __attribute__((packed)) authPolicy;
            uint16_t parameters_keyedHashDetail_scheme_scheme;
            struct {
                uint16_t size;
                uint8_t  buffer[32];
            } __attribute__((packed)) unique_keyedHash;
        } __attribute__((packed)) publicArea;
    } __attribute__((packed)) outPublic;
    struct {
        uint16_t size;
        uint8_t  name[34];
    } __attribute__((packed)) name[2];
} __attribute__((packed)) TPM2_CC_ReadPublic_Response_t;

static inline __attribute__((nonnull))
void unsealconv_ReadPublic_request(
    TPM2_CC_ReadPublic_Request_t *out_req,
    const uint32_t in_objectHandle
) {
    *out_req = (TPM2_CC_ReadPublic_Request_t){
        {   
            htons(0x8001),              // TPM_ST.NO_SESSIONS
            htons(sizeof(*out_req)),    // 14 (0xe)
            htons(0x173)                // TPM_CC.ReadPublic
        },
        htonl(in_objectHandle)          // e.g. 0x81000000 (TPM_HR.PERSISTENT.000000)
    };
}

// Retrieve name of object for use in HMAC for Unseal
static inline __attribute__((nonnull))
uint8_t unsealconv_ReadPublic_response(
    const TPM2_CC_ReadPublic_Response_t *in_resp,
    uint8_t (*out_name)[2+SHA256_SIZE_BYTES]
) {
    uint8_t is_ok = 0xFF;
    is_ok ^= (1<<0) * (in_resp->header.size == htons(sizeof(*in_resp))); // htons(162);
    is_ok ^= (1<<1) * (in_resp->header.code == 0);
    is_ok ^= (1<<2) * (in_resp->outPublic.size == htons(sizeof(in_resp->outPublic))); // htons(78);
    is_ok ^= (1<<3) * (in_resp->outPublic.publicArea.authPolicy.size == htons(SHA256_SIZE_BYTES));
    is_ok ^= (1<<4) * (in_resp->outPublic.publicArea.unique_keyedHash.size == htons(SHA256_SIZE_BYTES));
    is_ok ^= (1<<5) * (in_resp->name[0].size == htons(2+SHA256_SIZE_BYTES));
    is_ok ^= (1<<6) * (in_resp->name[1].size == htons(2+SHA256_SIZE_BYTES));
    if( is_ok == 0xFF ) {
        memcpy(out_name, in_resp->name[0].name, in_resp->name[0].size);
        return 0;
    }
    return is_ok;
}

static inline __attribute__((nonnull))
const CHAR16* unsealconv_ReadPublic(
    EFI_TREE_PROTOCOL *in_tree,
    const uint32_t in_objectHandle,
    uint8_t (*out_name)[2+SHA256_SIZE_BYTES]
) {
    TPM2_CC_ReadPublic_Request_t req;
    unsealconv_ReadPublic_request(&req, in_objectHandle);

    TPM2_CC_ReadPublic_Response_t resp;
    EFI_STATUS err = TrEE_SubmitCommand(in_tree, &req, &resp);
    if( EFI_ERROR(err) ) {
        return L"E" LINE_AS_STR;
    }

    if( unsealconv_ReadPublic_response(&resp, out_name) ) {
        return L"E" LINE_AS_STR;
    }

    return NULL;
}


// ------------------------------------------------------------------


typedef struct {
    TPM2_Header_t header;
    uint32_t policySession;
    uint16_t pcrDigest_size; // always 0, so pcrDigest buffer is skipped
    uint32_t pcrs_count;
    uint16_t pcrs_0_hash;
    uint8_t  pcrs_0_sizeofSelect;
    uint8_t  pcrs_0_pcrSelect[3];
} __attribute__((packed)) TPM2_CC_PolicyPCR_Request_t;

typedef struct {
    TPM2_Header_t header;
} __attribute__((packed)) TPM2_CC_PolicyPCR_Response_t;

static inline __attribute__((nonnull))
void unsealconv_PolicyPCR_request(
    TPM2_CC_PolicyPCR_Request_t *out_req,
    const uint32_t in_policySession
) {
    *out_req = (TPM2_CC_PolicyPCR_Request_t){
        {
            htons(0x8001),              // .tag = TPM_ST.NO_SESSIONS
            htonl(sizeof(*out_req)),    // .commandSize == 58
            htonl(0x017f)               // .commandCode = TPM_CC.PolicyPCR
        },
        htonl(in_policySession),        // handles.policySession
        htons(0),                       // parameters.pcrDigest.size
        htonl(1),                       // parameters.pcrs.count
        htons(0xb),                     // parameters.pcrs.pcrSelections[0].hash
        3,                              // parameters.pcrs.pcrSelections[0].sizeofSelect
        {0xFF, 0x00, 0x00}              // parameters.pcrs.pcrSelections[0].pcrSelect
    };
}

static inline __attribute__((nonnull))
uint8_t unsealconv_PolicyPCR_response(
    TPM2_CC_PolicyPCR_Response_t *in_resp
) {
    uint32_t is_ok = 0xFF;
    is_ok ^= (1<<0) * (in_resp->header.tag == htons(0x8001));               // TPM_ST.NO_SESSIONS
    is_ok ^= (1<<1) * (in_resp->header.size == htonl(sizeof(*in_resp)));    // 0xa
    is_ok ^= (1<<2) * (in_resp->header.code == 0);                          // TPM_RC.SUCCESS
    if( is_ok == 0xFF ) {
        return 0;
    }
    return is_ok;
}

static inline __attribute__((nonnull))
const CHAR16* unsealconv_PolicyPCR(
    EFI_TREE_PROTOCOL *in_tree,
    const uint32_t in_policySession
) {
    TPM2_CC_PolicyPCR_Request_t req;
    unsealconv_PolicyPCR_request(&req, in_policySession);

    TPM2_CC_PolicyPCR_Response_t resp;
    EFI_STATUS err = TrEE_SubmitCommand(in_tree, &req, &resp);
    if( EFI_ERROR(err) ) {
        return L"E" LINE_AS_STR;
    }

    if( unsealconv_PolicyPCR_response(&resp) ) {
        return L"E" LINE_AS_STR;
    }

    return NULL;
}


// ------------------------------------------------------------------


typedef struct {
    TPM2_Header_t header;
    uint32_t itemHandle;
    uint32_t authSize;
    struct {
        uint32_t sessionHandle;
        uint16_t nonce_size;
        uint8_t  nonce_buffer[SHA256_SIZE_BYTES];
        uint8_t  sessionAttributes;
        uint16_t hmac_size;
        uint8_t  hmac_buffer[SHA256_SIZE_BYTES];
    } __attribute__((packed)) auth;
} __attribute__((packed)) TPM2_CC_Unseal_Request_t;

typedef struct {
    TPM2_Header_t header;
    uint32_t parameterSize;
    uint16_t outData_size;
    uint8_t  outData_buffer[SHA256_SIZE_BYTES];
    uint16_t nonce_size;
    uint8_t  nonce_buffer[SHA256_SIZE_BYTES];
    uint8_t  sessionAttributes;
    uint16_t hmac_size;
    uint8_t  hmac_buffer[SHA256_SIZE_BYTES];
} __attribute__((packed)) TPM2_CC_Unseal_Response_t;

static inline __attribute__((nonnull))
void unsealconv_Unseal_request(
    TPM2_CC_Unseal_Request_t *out_req,
    const uint32_t in_itemHandle,
    const uint32_t in_sessionHandle,
    const uint8_t in_objName[2+SHA256_SIZE_BYTES],
    const uint8_t in_nonceTPM[SHA256_SIZE_BYTES]
) {
    *out_req = (TPM2_CC_Unseal_Request_t){
        {
            htons(0x8002),              // .tag = TPM_ST.SESSIONS
            htonl(sizeof(*out_req)),    // .commandSize == 91
            htonl(0x0000015e)           // .commandCode = TPM_CC.Unseal
        },
        htonl(in_itemHandle),           // .handles.itemHandle
        htonl(sizeof(out_req->auth)),   // .authSize == 73
        {
            htonl(in_sessionHandle),    // .authorizationArea[0].sessionHandle
            htons(SHA256_SIZE_BYTES),   // .authorizationArea[0].nonce.size
            {0},                        // .authorizationArea[0].nonce.buffer
            1,                          // .authorizationArea[0].sessionAttributes = continueSession
            htons(SHA256_SIZE_BYTES),   // .authorizationArea[0].hmac.size
            {0},                        // .authorizationArea[0].hmac.buffer
        }
    };

    // Context digest, we re-use this as the nonce even though we shouldn't
    // (nonce re-use doesn't matter in this case as it's not used for encryption,
    //  and the TPM nonce prevents somebody from sniping the key by sending carefully timed command)
    {        
        sha256_context ctx;
        const uint8_t x[4] = {0x00, 0x00, 0x01, 0x5e};  // TPM_CC.Unseal

        sha256_init(&ctx);
        sha256_update(&ctx, &x, sizeof(x));
        sha256_update(&ctx, in_objName, 2+SHA256_SIZE_BYTES);
        sha256_final(&ctx, out_req->auth.nonce_buffer);
    }

    // Fill msg buffer and produce final hmac digest
    {
        struct {
            uint8_t a[SHA256_SIZE_BYTES];
            uint8_t b[SHA256_SIZE_BYTES];
            uint8_t c[SHA256_SIZE_BYTES];
            uint8_t d;
        } __attribute__((packed)) tmp;

        const uint8_t *ctx_digest = out_req->auth.nonce_buffer;
        memcpy(&tmp.a, ctx_digest, SHA256_SIZE_BYTES);   // context digest
        memcpy(&tmp.b, ctx_digest, SHA256_SIZE_BYTES);   // our nonce
        memcpy(&tmp.c, in_nonceTPM, SHA256_SIZE_BYTES);  // TPM nonce
        tmp.d = 1;                                          // session attributes

        const uint8_t x = 0;
        hmac_sha256(out_req->auth.hmac_buffer, (const uint8_t*)&tmp, sizeof(tmp), &x, 0);
    }
}

static inline __attribute__((nonnull))
uint32_t unsealconv_Unseal_response(
    const TPM2_CC_Unseal_Response_t *in_resp,
    uint8_t (*out_secret)[SHA256_SIZE_BYTES]
) {
    uint32_t is_ok = 0xFF;
    is_ok ^= (1<<0) * (in_resp->header.tag == htons(0x8002));
    is_ok ^= (1<<1) * (in_resp->header.size == htonl(sizeof(*in_resp))); // htonl(75);
    is_ok ^= (1<<2) * (in_resp->header.code == 0);
    is_ok ^= (1<<3) * (in_resp->parameterSize == htonl(2+SHA256_SIZE_BYTES)); // XXX: why is this 34? This is the object name ?
    is_ok ^= (1<<4) * (in_resp->outData_size == htons(SHA256_SIZE_BYTES));
    is_ok ^= (1<<5) * (in_resp->nonce_size == htons(SHA256_SIZE_BYTES));
    is_ok ^= (1<<6) * (in_resp->hmac_size == htons(SHA256_SIZE_BYTES));
    if( is_ok == 0xFF ) {
        memcpy(out_secret, in_resp->outData_buffer, SHA256_SIZE_BYTES);
        return 0;
    }
    return is_ok;
}

static inline __attribute__((nonnull))
const CHAR16* unsealconv_Unseal(
    EFI_TREE_PROTOCOL *in_tree,
    const uint32_t in_objectHandle,
    const uint32_t in_sessionHandle,
    const uint8_t in_objName[2+SHA256_SIZE_BYTES],
    const uint8_t in_nonceTPM[SHA256_SIZE_BYTES],
    uint8_t (*out_secret)[SHA256_SIZE_BYTES]
) {
    TPM2_CC_Unseal_Request_t req;
    unsealconv_Unseal_request(&req, in_objectHandle, in_sessionHandle, in_objName, in_nonceTPM);

    TPM2_CC_Unseal_Response_t resp;
    EFI_STATUS err = TrEE_SubmitCommand(in_tree, &req, &resp);
    if( EFI_ERROR(err) ) {
        return L"E" LINE_AS_STR;
    }

    if( unsealconv_Unseal_response(&resp, out_secret) ) {
        return L"E" LINE_AS_STR;
    }

    return NULL;
}


// ------------------------------------------------------------------


typedef struct {
    TPM2_Header_t header;
    uint32_t flushHandle;
} __attribute__((packed)) TPM2_CC_FlushContext_Request_t;

static inline __attribute__((nonnull))
const CHAR16* unsealconv_FlushContext(
    EFI_TREE_PROTOCOL *in_tree,
    const uint32_t in_sessionHandle
) {
    TPM2_CC_FlushContext_Request_t req = {
        {
            htons(0x8001),      // .tag = TPM_ST.NO_SESSIONS
            htonl(sizeof(req)), // .commandSize = 0xe (14)
            htonl(0x0165)       // .commandCode = TPM_CC.FlushContext
        },
        htonl(in_sessionHandle) // .handles.flushHandle
    };

    TPM2_Header_t resp;
    EFI_STATUS err = TrEE_SubmitCommand(in_tree, &req, &resp);
    if( EFI_ERROR(err) ) {
        return L"E" LINE_AS_STR;
    }

    if( resp.code != 0 || resp.code != htonl(sizeof(resp)) ) {
        return L"E" LINE_AS_STR;
    }

    return NULL;
}


// ------------------------------------------------------------------


static inline __attribute__((nonnull,always_inline))
const CHAR16* buttlocker (
    EFI_BOOT_SERVICES *BS,
    const uint32_t in_objectHandle,             // Persistent object handle
    uint8_t (*out_secret)[SHA256_SIZE_BYTES]    // Retrieved secret
) {
    EFI_TREE_PROTOCOL *tree = NULL;

    // Locate TrEE protocol to communicate with TPM via UEFI firmware interface
    {
        EFI_GUID tree_guid = EFI_TREE_PROTOCOL_GUID;
        EFI_STATUS err = uefi_call_wrapper(BS->LocateProtocol, 3, &tree_guid, NULL, (VOID **)&tree);
        if( EFI_ERROR(err) ) {
            return L"E" LINE_AS_STR;
        }
    }

    // Perform the unsealing
    {        
        const CHAR16 *err_text;

        // Check object exists before unsealing
        uint8_t object_name[2+SHA256_SIZE_BYTES];
        err_text = unsealconv_ReadPublic(tree, in_objectHandle, &object_name);
        if( err_text != NULL ) {
            return err_text;
        }

        uint32_t policySession;
        uint8_t nonceTPM[SHA256_SIZE_BYTES];
        err_text = unsealconv_StartAuthSession(tree, &policySession, &nonceTPM);
        if( err_text != NULL ) {
            return err_text;
        }

        err_text = unsealconv_PolicyPCR(tree, policySession);
        if( err_text == NULL )
        {   // Only unseal if PCR policy could be applied
            err_text = unsealconv_Unseal(tree, in_objectHandle, policySession, object_name, nonceTPM, out_secret);
        }

        // Always flush if auth session has been started
        unsealconv_FlushContext(tree, policySession);

        if( err_text != NULL )
        {   // Return previous error message, ignoring any error from FlushContext
            return err_text;
        }

        // TODO: extend PCR to make it impossible to retrieve secret again
    }

    return NULL;
}

static inline __attribute__((nonnull,always_inline))
int buttlocker_decrypt(uint8_t (*key)[32], uint8_t nonce, uint8_t *buf, size_t buf_len)
{
    // buffer has 16 byte tag then 16 byte IV appended to it
    uint32_t st[12];
    uc_state_init(st, *key, buf+(buf_len-XOODOO_IV_SIZE));
    return 0 == uc_decrypt(st,
                           buf,
                           buf_len-(XOODOO_TAG_SIZE+XOODOO_IV_SIZE),
                           buf+(buf_len-(XOODOO_TAG_SIZE+XOODOO_IV_SIZE)),
                           XOODOO_TAG_SIZE);
}


// ------------------------------------------------------------------

// BUTTLOCKER_C_
#endif
