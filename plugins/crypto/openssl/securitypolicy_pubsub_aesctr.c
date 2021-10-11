/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2021 (c) Wind River Systems, Inc.
 */

#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/util.h>
#include "securitypolicy_openssl_common.h"

#ifdef UA_ENABLE_PUBSUB_ENCRYPTION_OPENSSL

#include <openssl/rand.h>

/*
 * PubSub crypto provider for OpenSSL
 *
 * Supported security policies:
 * - PubSub-Aes128-CTR
 * - PubSub-Aes256-CTR
 */

#define UA_SHA256_LENGTH 32
#define UA_AESCTR_SIGNING_KEY_LENGTH 32
#define UA_AES128CTR_KEY_LENGTH 16
#define UA_AES256CTR_KEY_LENGTH 32
#define UA_AESCTR_KEYNONCE_LENGTH 4
#define UA_AESCTR_MESSAGENONCE_LENGTH 8
#define UA_AESCTR_ENCRYPTION_BLOCK_SIZE 16
#define UA_AESCTR_PLAIN_TEXT_BLOCK_SIZE 16
/* counter block=keynonce(4Byte)+Messagenonce(8Byte)+counter(4Byte) see Part14
 * 7.2.2.2.3.2 for details */
#define UA_AESCTR_COUNTERBLOCK_SIZE 16

typedef struct {
    const UA_PubSubSecurityPolicy *securityPolicy;
} PUBSUB_AESCTR_PolicyContext;

typedef struct {
    PUBSUB_AESCTR_PolicyContext *policyContext;
    UA_Byte signingKey[UA_AESCTR_SIGNING_KEY_LENGTH];
    UA_Byte encryptingKey[UA_AES256CTR_KEY_LENGTH];
    UA_Byte keyNonce[UA_AESCTR_KEYNONCE_LENGTH];
    UA_Byte messageNonce[UA_AESCTR_MESSAGENONCE_LENGTH];
} PUBSUB_AESCTR_ChannelContext;


/*******************/
/* SymmetricModule */
/*******************/

/* Signature and verify all using HMAC-SHA2-256, nothing to change */
static UA_StatusCode
verify_sp_pubsub_aesctr(PUBSUB_AESCTR_ChannelContext *cc,
                        const UA_ByteString *message,
                        const UA_ByteString *signature) {
    if(cc == NULL || message == NULL || signature == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    if(signature->length != UA_SHA256_LENGTH)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    /* Verify the Signature */

    UA_ByteString signingKey =
        {UA_AESCTR_SIGNING_KEY_LENGTH, cc->signingKey};

    UA_StatusCode ret = UA_OpenSSL_HMAC_SHA256_Verify (message,
                                                       &signingKey,
                                                       signature);
    if (ret != UA_STATUSCODE_GOOD)
        ret = UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    return ret;
}

static UA_StatusCode
sign_sp_pubsub_aesctr(PUBSUB_AESCTR_ChannelContext *cc,
                      const UA_ByteString *message, UA_ByteString *signature) {
    if(signature->length != UA_SHA256_LENGTH)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_ByteString signingKey =
        {UA_AESCTR_SIGNING_KEY_LENGTH, cc->signingKey};

    return UA_OpenSSL_HMAC_SHA256_Sign (message,
                                        &signingKey,
                                        signature);
}

static size_t
getSignatureSize_sp_pubsub_aesctr(const void *channelContext) {
    return UA_SHA256_LENGTH;
}

static size_t
getSigningKeyLength_sp_pubsub_aesctr(const void *const channelContext) {
    return UA_AESCTR_SIGNING_KEY_LENGTH;
}

static size_t
getEncryptionKeyLength_sp_pubsub_aes128ctr(const void *channelContext) {
    return UA_AES128CTR_KEY_LENGTH;
}

static size_t
getEncryptionKeyLength_sp_pubsub_aes256ctr(const void *channelContext) {
    return UA_AES256CTR_KEY_LENGTH;
}

static size_t
getEncryptionBlockSize_sp_pubsub_aesctr(const void *channelContext) {
    return UA_AESCTR_ENCRYPTION_BLOCK_SIZE;
}

static size_t
getPlainTextBlockSize_sp_pubsub_aesctr(const void *channelContext) {
    return UA_AESCTR_PLAIN_TEXT_BLOCK_SIZE;
}

static UA_StatusCode
encrypt_sp_pubsub_aesctr(PUBSUB_AESCTR_ChannelContext *cc,
                         UA_ByteString *data) {
    if(cc == NULL || data == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    if(cc->policyContext == NULL || cc->policyContext->securityPolicy == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    const UA_SecurityPolicySymmetricModule *symmetricModule =
        &cc->policyContext->securityPolicy->symmetricModule;
    const UA_SecurityPolicyEncryptionAlgorithm *encryptionAlgorithm =
        &symmetricModule->cryptoModule.encryptionAlgorithm;

    UA_Byte counterBlockCopy[UA_AESCTR_ENCRYPTION_BLOCK_SIZE];
    memcpy(counterBlockCopy, cc->keyNonce, UA_AESCTR_KEYNONCE_LENGTH);
    memcpy(counterBlockCopy + UA_AESCTR_KEYNONCE_LENGTH,
           cc->messageNonce, UA_AESCTR_MESSAGENONCE_LENGTH);
    memset(counterBlockCopy + UA_AESCTR_KEYNONCE_LENGTH +
           UA_AESCTR_MESSAGENONCE_LENGTH, 0, 4);

    UA_ByteString counterBlockCopyString =
        {UA_AESCTR_ENCRYPTION_BLOCK_SIZE, counterBlockCopy};

    size_t keyLength = encryptionAlgorithm->getLocalKeyLength (cc);
    UA_ByteString encryptingKeyString = {keyLength, cc->encryptingKey};

    if (keyLength == UA_AES128CTR_KEY_LENGTH)
        {

        (void) UA_OpenSSL_AES_128_CTR_Encrypt (&counterBlockCopyString,
                                               &encryptingKeyString,
                                               data);
        }
    else if (keyLength == UA_AES256CTR_KEY_LENGTH)
        {
        (void) UA_OpenSSL_AES_256_CTR_Encrypt (&counterBlockCopyString,
                                               &encryptingKeyString,
                                               data);
        }
    else
        {
        return UA_STATUSCODE_BADINTERNALERROR;
        }

    return UA_STATUSCODE_GOOD;
}

/* a decryption function is exactly the same as an encryption one, since they all do XOR
 * operations*/
static UA_StatusCode
decrypt_sp_pubsub_aesctr(PUBSUB_AESCTR_ChannelContext *cc,
                         UA_ByteString *data) {

    if(cc == NULL || data == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    if(cc->policyContext == NULL || cc->policyContext->securityPolicy == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    const UA_SecurityPolicySymmetricModule *symmetricModule =
        &cc->policyContext->securityPolicy->symmetricModule;
    const UA_SecurityPolicyEncryptionAlgorithm *encryptionAlgorithm =
        &symmetricModule->cryptoModule.encryptionAlgorithm;

    /* Prepare the counterBlock required for encryption/decryption */
    UA_Byte counterBlockCopy[UA_AESCTR_ENCRYPTION_BLOCK_SIZE];
    memcpy(counterBlockCopy, cc->keyNonce, UA_AESCTR_KEYNONCE_LENGTH);
    memcpy(counterBlockCopy + UA_AESCTR_KEYNONCE_LENGTH,
           cc->messageNonce, UA_AESCTR_MESSAGENONCE_LENGTH);
    memset(counterBlockCopy + UA_AESCTR_KEYNONCE_LENGTH +
           UA_AESCTR_MESSAGENONCE_LENGTH, 0, 4);

    UA_ByteString counterBlockCopyString =
        {UA_AESCTR_ENCRYPTION_BLOCK_SIZE, counterBlockCopy};

    size_t keyLength = encryptionAlgorithm->getRemoteKeyLength (cc);
    UA_ByteString encryptingKeyString = {keyLength, cc->encryptingKey};

    if (keyLength == UA_AES128CTR_KEY_LENGTH)
        {

        (void) UA_OpenSSL_AES_128_CTR_Decrypt (&counterBlockCopyString,
                                               &encryptingKeyString,
                                               data);
        }
    else if (keyLength == UA_AES256CTR_KEY_LENGTH)
        {
        (void) UA_OpenSSL_AES_256_CTR_Decrypt (&counterBlockCopyString,
                                               &encryptingKeyString,
                                               data);
        }
    else
        {
        return UA_STATUSCODE_BADINTERNALERROR;
        }

   return UA_STATUSCODE_GOOD;
}

/*Tested, meeting  Profile*/
static UA_StatusCode
generateKey_sp_pubsub_aesctr(void *policyContext, const UA_ByteString *secret,
                             const UA_ByteString *seed, UA_ByteString *out) {
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

/* This nonce does not need to be a cryptographically random number, it can be
 * pseudo-random */
static UA_StatusCode
generateNonce_sp_pubsub_aesctr(void *policyContext, UA_ByteString *out) {
    if(policyContext == NULL || out == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_Int32 rc = RAND_bytes(out->data, (int) out->length);
    if (rc != 1) {
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    }
    return UA_STATUSCODE_GOOD;
}

/*****************/
/* ChannelModule */
/*****************/

static void
channelContext_deleteContext_sp_pubsub_aesctr(PUBSUB_AESCTR_ChannelContext *cc) {
    UA_free(cc);
}

static UA_StatusCode
channelContext_newContext_sp_pubsub_aesctr(void *policyContext,
                                           const UA_ByteString *signingKey,
                                           const UA_ByteString *encryptingKey,
                                           const UA_ByteString *keyNonce,
                                           void **wgContext) {
    if((signingKey && signingKey->length != UA_AESCTR_SIGNING_KEY_LENGTH) ||
       (encryptingKey && (encryptingKey->length != UA_AES128CTR_KEY_LENGTH &&
                          encryptingKey->length != UA_AES256CTR_KEY_LENGTH)) ||
       (keyNonce && keyNonce->length != UA_AESCTR_KEYNONCE_LENGTH))
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    /* Allocate the channel context */
    PUBSUB_AESCTR_ChannelContext *cc = (PUBSUB_AESCTR_ChannelContext *)
        UA_calloc(1, sizeof(PUBSUB_AESCTR_ChannelContext));
    if(cc == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    /* Initialize the channel context */
    cc->policyContext = (PUBSUB_AESCTR_PolicyContext *)policyContext;
    if(signingKey)
        memcpy(cc->signingKey, signingKey->data, signingKey->length);
    if(encryptingKey)
        memcpy(cc->encryptingKey, encryptingKey->data, encryptingKey->length);
    if(keyNonce)
        memcpy(cc->keyNonce, keyNonce->data, keyNonce->length);
    *wgContext = cc;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
channelContext_setKeys_sp_pubsub_aesctr(PUBSUB_AESCTR_ChannelContext *cc,
                                        const UA_ByteString *signingKey,
                                        const UA_ByteString *encryptingKey,
                                        const UA_ByteString *keyNonce) {
    if(!cc)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(!signingKey || signingKey->length != UA_AESCTR_SIGNING_KEY_LENGTH ||
       !encryptingKey || (encryptingKey->length != UA_AES128CTR_KEY_LENGTH &&
                          encryptingKey->length != UA_AES256CTR_KEY_LENGTH) ||
       !keyNonce || keyNonce->length != UA_AESCTR_KEYNONCE_LENGTH)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    memcpy(cc->signingKey, signingKey->data, signingKey->length);
    memcpy(cc->encryptingKey, encryptingKey->data, encryptingKey->length);
    memcpy(cc->keyNonce, keyNonce->data, keyNonce->length);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
channelContext_setMessageNonce_sp_pubsub_aesctr(PUBSUB_AESCTR_ChannelContext *cc,
                                                const UA_ByteString *nonce) {
    if(nonce->length != UA_AESCTR_MESSAGENONCE_LENGTH)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    memcpy(cc->messageNonce, nonce->data, nonce->length);
    return UA_STATUSCODE_GOOD;
}

static void
deleteMembers_sp_pubsub_aesctr(UA_PubSubSecurityPolicy *securityPolicy) {
    if(securityPolicy == NULL)
        return;

    if(securityPolicy->policyContext == NULL)
        return;

    /* delete all allocated members in the context */
    PUBSUB_AESCTR_PolicyContext *pc =
        (PUBSUB_AESCTR_PolicyContext *)securityPolicy->policyContext;

    UA_LOG_DEBUG(securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                 "Deleted members of EndpointContext for sp_PUBSUB_AESCTR");
    UA_free(pc);
    securityPolicy->policyContext = NULL;
}

static UA_StatusCode
policyContext_newContext_sp_pubsub_aesctr(UA_PubSubSecurityPolicy *securityPolicy) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(securityPolicy == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    PUBSUB_AESCTR_PolicyContext *pc = (PUBSUB_AESCTR_PolicyContext *)
        UA_calloc(1, sizeof(PUBSUB_AESCTR_PolicyContext));
    securityPolicy->policyContext = (void *)pc;
    if(!pc) {
        retval = UA_STATUSCODE_BADOUTOFMEMORY;
        goto error;
    }

    /* Initialize the PolicyContext */
    memset(pc, 0, sizeof(PUBSUB_AESCTR_PolicyContext));
    pc->securityPolicy = securityPolicy;

    /* Assume the RNG is seeded for OpenSSL */

    return retval;

error:
    UA_LOG_ERROR(securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                 "Could not create securityContext");
    if(securityPolicy->policyContext != NULL)
        deleteMembers_sp_pubsub_aesctr(securityPolicy);
    return retval;
}

UA_StatusCode
UA_PubSubSecurityPolicy_Aes128Ctr(UA_PubSubSecurityPolicy *policy,
                                  const UA_Logger *logger) {
    UA_Openssl_Init();

    memset(policy, 0, sizeof(UA_PubSubSecurityPolicy));
    policy->logger = logger;

    policy->policyUri =
        UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR");

    UA_SecurityPolicySymmetricModule *symmetricModule = &policy->symmetricModule;

    /* SymmetricModule */
    symmetricModule->generateKey = generateKey_sp_pubsub_aesctr;
    symmetricModule->generateNonce = generateNonce_sp_pubsub_aesctr;

    UA_SecurityPolicySignatureAlgorithm *signatureAlgorithm =
        &symmetricModule->cryptoModule.signatureAlgorithm;
    signatureAlgorithm->uri = UA_STRING("http://www.w3.org/2001/04/xmlenc#sha256");
    signatureAlgorithm->verify =
        (UA_StatusCode(*)(void *, const UA_ByteString *,
                          const UA_ByteString *))verify_sp_pubsub_aesctr;
    signatureAlgorithm->sign =
        (UA_StatusCode(*)(void *, const UA_ByteString *, UA_ByteString *))sign_sp_pubsub_aesctr;
    signatureAlgorithm->getLocalSignatureSize = getSignatureSize_sp_pubsub_aesctr;
    signatureAlgorithm->getRemoteSignatureSize = getSignatureSize_sp_pubsub_aesctr;
    signatureAlgorithm->getLocalKeyLength =
        (size_t(*)(const void *))getSigningKeyLength_sp_pubsub_aesctr;
    signatureAlgorithm->getRemoteKeyLength =
        (size_t(*)(const void *))getSigningKeyLength_sp_pubsub_aesctr;

    UA_SecurityPolicyEncryptionAlgorithm *encryptionAlgorithm =
        &symmetricModule->cryptoModule.encryptionAlgorithm;
    encryptionAlgorithm->uri =
        UA_STRING("https://tools.ietf.org/html/rfc3686"); /* Temp solution */
    encryptionAlgorithm->encrypt =
        (UA_StatusCode(*)(void *, UA_ByteString *))encrypt_sp_pubsub_aesctr;
    encryptionAlgorithm->decrypt =
        (UA_StatusCode(*)(void *, UA_ByteString *))decrypt_sp_pubsub_aesctr;
    encryptionAlgorithm->getLocalKeyLength =
        getEncryptionKeyLength_sp_pubsub_aes128ctr;
    encryptionAlgorithm->getRemoteKeyLength =
        getEncryptionKeyLength_sp_pubsub_aes128ctr;
    encryptionAlgorithm->getRemoteBlockSize =
        (size_t(*)(const void *))getEncryptionBlockSize_sp_pubsub_aesctr;
    encryptionAlgorithm->getRemotePlainTextBlockSize =
        (size_t(*)(const void *))getPlainTextBlockSize_sp_pubsub_aesctr;
    symmetricModule->secureChannelNonceLength = UA_AESCTR_SIGNING_KEY_LENGTH +
        UA_AES128CTR_KEY_LENGTH + UA_AESCTR_KEYNONCE_LENGTH;

    /* ChannelModule */
    policy->newContext = channelContext_newContext_sp_pubsub_aesctr;
    policy->deleteContext = (void (*)(void *))
        channelContext_deleteContext_sp_pubsub_aesctr;

    policy->setSecurityKeys = (UA_StatusCode(*)(void *, const UA_ByteString *,
                                                const UA_ByteString *,
                                                const UA_ByteString *))
            channelContext_setKeys_sp_pubsub_aesctr;
    policy->setMessageNonce = (UA_StatusCode(*)(void *, const UA_ByteString *))
        channelContext_setMessageNonce_sp_pubsub_aesctr;
    policy->clear = deleteMembers_sp_pubsub_aesctr;
    policy->policyContext = NULL;

    /* Initialize the policyContext */
    return policyContext_newContext_sp_pubsub_aesctr(policy);
}

UA_StatusCode
UA_PubSubSecurityPolicy_Aes256Ctr(UA_PubSubSecurityPolicy *policy,
                                  const UA_Logger *logger) {
    UA_Openssl_Init();

    memset(policy, 0, sizeof(UA_PubSubSecurityPolicy));
    policy->logger = logger;

    policy->policyUri =
        UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR");

    UA_SecurityPolicySymmetricModule *symmetricModule = &policy->symmetricModule;

    /* SymmetricModule */
    symmetricModule->generateKey = generateKey_sp_pubsub_aesctr;
    symmetricModule->generateNonce = generateNonce_sp_pubsub_aesctr;

    UA_SecurityPolicySignatureAlgorithm *signatureAlgorithm =
        &symmetricModule->cryptoModule.signatureAlgorithm;
    signatureAlgorithm->uri = UA_STRING("http://www.w3.org/2001/04/xmlenc#sha256");
    signatureAlgorithm->verify =
        (UA_StatusCode(*)(void *, const UA_ByteString *,
                          const UA_ByteString *))verify_sp_pubsub_aesctr;
    signatureAlgorithm->sign =
        (UA_StatusCode(*)(void *, const UA_ByteString *, UA_ByteString *))sign_sp_pubsub_aesctr;
    signatureAlgorithm->getLocalSignatureSize = getSignatureSize_sp_pubsub_aesctr;
    signatureAlgorithm->getRemoteSignatureSize = getSignatureSize_sp_pubsub_aesctr;
    signatureAlgorithm->getLocalKeyLength =
        (size_t(*)(const void *))getSigningKeyLength_sp_pubsub_aesctr;
    signatureAlgorithm->getRemoteKeyLength =
        (size_t(*)(const void *))getSigningKeyLength_sp_pubsub_aesctr;

    UA_SecurityPolicyEncryptionAlgorithm *encryptionAlgorithm =
        &symmetricModule->cryptoModule.encryptionAlgorithm;
    encryptionAlgorithm->uri =
        UA_STRING("https://tools.ietf.org/html/rfc3686"); /* Temp solution */
    encryptionAlgorithm->encrypt =
        (UA_StatusCode(*)(void *, UA_ByteString *))encrypt_sp_pubsub_aesctr;
    encryptionAlgorithm->decrypt =
        (UA_StatusCode(*)(void *, UA_ByteString *))decrypt_sp_pubsub_aesctr;
    encryptionAlgorithm->getLocalKeyLength =
        getEncryptionKeyLength_sp_pubsub_aes256ctr;
    encryptionAlgorithm->getRemoteKeyLength =
        getEncryptionKeyLength_sp_pubsub_aes256ctr;
    encryptionAlgorithm->getRemoteBlockSize =
        (size_t(*)(const void *))getEncryptionBlockSize_sp_pubsub_aesctr;
    encryptionAlgorithm->getRemotePlainTextBlockSize =
        (size_t(*)(const void *))getPlainTextBlockSize_sp_pubsub_aesctr;
    symmetricModule->secureChannelNonceLength = UA_AESCTR_SIGNING_KEY_LENGTH +
        UA_AES256CTR_KEY_LENGTH + UA_AESCTR_KEYNONCE_LENGTH;

    /* ChannelModule */
    policy->newContext = channelContext_newContext_sp_pubsub_aesctr;
    policy->deleteContext = (void (*)(void *))
        channelContext_deleteContext_sp_pubsub_aesctr;

    policy->setSecurityKeys = (UA_StatusCode(*)(void *, const UA_ByteString *,
                                                const UA_ByteString *,
                                                const UA_ByteString *))
            channelContext_setKeys_sp_pubsub_aesctr;
    policy->setMessageNonce = (UA_StatusCode(*)(void *, const UA_ByteString *))
        channelContext_setMessageNonce_sp_pubsub_aesctr;
    policy->clear = deleteMembers_sp_pubsub_aesctr;
    policy->policyContext = NULL;

    /* Initialize the policyContext */
    return policyContext_newContext_sp_pubsub_aesctr(policy);
}

#endif
