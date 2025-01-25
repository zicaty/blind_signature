// PKCS#11接口定义

namespace cpp svc.p11
namespace java kl.hsm.server.svc.p11

/**
 * General
 * thrift不支持无符号整型, 对最高位为1的整数使用负数来表示
 */
const i32 TCK_INVALID                   = -1
const i32 TCK_TRUE                      = 1
const i32 TCK_FALSE                     = 0
const i32 TCK_UNAVAILABLE_INFORMATION   = -1
const i32 TCK_EFFECTIVELY_INFINITE      = 0
const i32 TCK_INVALID_HANDLE            = 0
const i32 TCK_VENDOR                    = -2147483648 /* 0x80000000*/

/**
 * 对象类型
 */
enum ObjectClass{
  TCKO_DATA                = 0x00000000
  TCKO_CERTIFICATE         = 0x00000001
  TCKO_PUBLIC_KEY          = 0x00000002
  TCKO_PRIVATE_KEY         = 0x00000003
  TCKO_SECRET_KEY          = 0x00000004
  TCKO_HW_FEATURE          = 0x00000005
  TCKO_DOMAIN_PARAMETERS   = 0x00000006
  TCKO_MECHANISM           = 0x00000007
  TCKO_OTP_KEY             = 0x00000008
  TCKO_VENDOR_DEFINED      = -2147483648 /* 0x80000000*/
  TCKO_INVALID             = -1
}

/**
 * 密钥类型
 */
enum KeyType{
  TCKK_RSA                 = 0x00000000
  TCKK_DSA                 = 0x00000001
  TCKK_DH                  = 0x00000002
  TCKK_EC                  = 0x00000003
  TCKK_X9_42_DH            = 0x00000004
  TCKK_KEA                 = 0x00000005
  TCKK_GENERIC_SECRET      = 0x00000010
  TCKK_RC2                 = 0x00000011
  TCKK_RC4                 = 0x00000012
  TCKK_DES                 = 0x00000013
  TCKK_DES2                = 0x00000014
  TCKK_DES3                = 0x00000015
  TCKK_CAST                = 0x00000016
  TCKK_CAST3               = 0x00000017
  TCKK_CAST128             = 0x00000018
  TCKK_RC5                 = 0x00000019
  TCKK_IDEA                = 0x0000001A
  TCKK_SKIPJACK            = 0x0000001B
  TCKK_BATON               = 0x0000001C
  TCKK_JUNIPER             = 0x0000001D
  TCKK_CDMF                = 0x0000001E
  TCKK_AES                 = 0x0000001F
  TCKK_BLOWFISH            = 0x00000020
  TCKK_TWOFISH             = 0x00000021
  TCKK_SECURID             = 0x00000022
  TCKK_HOTP                = 0x00000023
  TCKK_ACTI                = 0x00000024
  TCKK_CAMELLIA            = 0x00000025
  TCKK_ARIA                = 0x00000026
  TCKK_MD5_HMAC            = 0x00000027
  TCKK_SHA_1_HMAC          = 0x00000028
  TCKK_RIPEMD128_HMAC      = 0x00000029
  TCKK_RIPEMD160_HMAC      = 0x0000002A
  TCKK_SHA256_HMAC         = 0x0000002B
  TCKK_SHA384_HMAC         = 0x0000002C
  TCKK_SHA512_HMAC         = 0x0000002D
  TCKK_SHA224_HMAC         = 0x0000002E

  TCKK_SEED                = 0x0000002F
  TCKK_VENDOR_DEFINED      = -2147483648 /* 0x80000000*/

  /* 格尔自定义密钥类型 */
  TCKK_SM1                 = -2147483647 /* 0x80000001*/
  TCKK_SM4                 = -2147483646 /* 0x80000002*/
  TCKK_SM2                 = -2147483644 /* 0x80000004*/
  TCKK_SM9                 = -2147483640 /* 0x80000008*/
  TCKK_INVALID             = -1
}

/**
 * 属性类型
 */
enum AttributeType{
  TCKA_CLASS                       = 0x00000000
  TCKA_TOKEN                       = 0x00000001
  TCKA_PRIVATE                     = 0x00000002
  TCKA_LABEL                       = 0x00000003
  TCKA_APPLICATION                 = 0x00000010
  TCKA_VALUE                       = 0x00000011
  TCKA_OBJECT_ID                   = 0x00000012
  TCKA_CERTIFICATE_TYPE            = 0x00000080
  TCKA_ISSUER                      = 0x00000081
  TCKA_SERIAL_NUMBER               = 0x00000082
  TCKA_AC_ISSUER                   = 0x00000083
  TCKA_OWNER                       = 0x00000084
  TCKA_ATTR_TYPES                  = 0x00000085
  TCKA_TRUSTED                     = 0x00000086
  TCKA_CERTIFICATE_CATEGORY        = 0x00000087
  TCKA_JAVA_MIDP_SECURITY_DOMAIN   = 0x00000088
  TCKA_URL                         = 0x00000089
  TCKA_HASH_OF_SUBJECT_PUBLIC_KEY  = 0x0000008A
  TCKA_HASH_OF_ISSUER_PUBLIC_KEY   = 0x0000008B
  TCKA_NAME_HASH_ALGORITHM         = 0x0000008C
  TCKA_CHECK_VALUE                 = 0x00000090
  TCKA_KEY_TYPE                    = 0x00000100
  TCKA_SUBJECT                     = 0x00000101
  TCKA_ID                          = 0x00000102
  TCKA_SENSITIVE                   = 0x00000103
  TCKA_ENCRYPT                     = 0x00000104
  TCKA_DECRYPT                     = 0x00000105
  TCKA_WRAP                        = 0x00000106
  TCKA_UNWRAP                      = 0x00000107
  TCKA_SIGN                        = 0x00000108
  TCKA_SIGN_RECOVER                = 0x00000109
  TCKA_VERIFY                      = 0x0000010A
  TCKA_VERIFY_RECOVER              = 0x0000010B
  TCKA_DERIVE                      = 0x0000010C
  TCKA_START_DATE                  = 0x00000110
  TCKA_END_DATE                    = 0x00000111
  TCKA_MODULUS                     = 0x00000120
  TCKA_MODULUS_BITS                = 0x00000121
  TCKA_PUBLIC_EXPONENT             = 0x00000122
  TCKA_PRIVATE_EXPONENT            = 0x00000123
  TCKA_PRIME_1                     = 0x00000124
  TCKA_PRIME_2                     = 0x00000125
  TCKA_EXPONENT_1                  = 0x00000126
  TCKA_EXPONENT_2                  = 0x00000127
  TCKA_COEFFICIENT                 = 0x00000128
  TCKA_PUBLIC_KEY_INFO             = 0x00000129
  TCKA_PRIME                       = 0x00000130
  TCKA_SUBPRIME                    = 0x00000131
  TCKA_BASE                        = 0x00000132
  TCKA_PRIME_BITS                  = 0x00000133
  TCKA_SUBPRIME_BITS               = 0x00000134
#   TCKA_SUB_PRIME_BITS              = 0x00000134
  TCKA_VALUE_BITS                  = 0x00000160
  TCKA_VALUE_LEN                   = 0x00000161
  TCKA_EXTRACTABLE                 = 0x00000162
  TCKA_LOCAL                       = 0x00000163
  TCKA_NEVER_EXTRACTABLE           = 0x00000164
  TCKA_ALWAYS_SENSITIVE            = 0x00000165
  TCKA_KEY_GEN_MECHANISM           = 0x00000166
  TCKA_MODIFIABLE                  = 0x00000170
  TCKA_COPYABLE                    = 0x00000171
  TCKA_DESTROYABLE                 = 0x00000172
  TCKA_EC_PARAMS                   = 0x00000180
  TCKA_EC_POINT                    = 0x00000181
  TCKA_SECONDARY_AUTH              = 0x00000200 /* Deprecated */
  TCKA_AUTH_PIN_FLAGS              = 0x00000201 /* Deprecated */
  TCKA_ALWAYS_AUTHENTICATE         = 0x00000202
  TCKA_WRAP_WITH_TRUSTED           = 0x00000210
  TCKA_WRAP_TEMPLATE               = 0x40000211
  TCKA_UNWRAP_TEMPLATE             = 0x40000212
  TCKA_DERIVE_TEMPLATE             = 0x40000213
  TCKA_OTP_FORMAT                  = 0x00000220
  TCKA_OTP_LENGTH                  = 0x00000221
  TCKA_OTP_TIME_INTERVAL           = 0x00000222
  TCKA_OTP_USER_FRIENDLY_MODE      = 0x00000223
  TCKA_OTP_CHALLENGE_REQUIREMENT   = 0x00000224
  TCKA_OTP_TIME_REQUIREMENT        = 0x00000225
  TCKA_OTP_COUNTER_REQUIREMENT     = 0x00000226
  TCKA_OTP_PIN_REQUIREMENT         = 0x00000227
  TCKA_OTP_COUNTER                 = 0x0000022E
  TCKA_OTP_TIME                    = 0x0000022F
  TCKA_OTP_USER_IDENTIFIER         = 0x0000022A
  TCKA_OTP_SERVICE_IDENTIFIER      = 0x0000022B
  TCKA_OTP_SERVICE_LOGO            = 0x0000022C
  TCKA_OTP_SERVICE_LOGO_TYPE       = 0x0000022D
  TCKA_GOSTR3410_PARAMS            = 0x00000250
  TCKA_GOSTR3411_PARAMS            = 0x00000251
  TCKA_GOST28147_PARAMS            = 0x00000252
  TCKA_HW_FEATURE_TYPE             = 0x00000300
  TCKA_RESET_ON_INIT               = 0x00000301
  TCKA_HAS_RESET                   = 0x00000302
  TCKA_PIXEL_X                     = 0x00000400
  TCKA_PIXEL_Y                     = 0x00000401
  TCKA_RESOLUTION                  = 0x00000402
  TCKA_CHAR_ROWS                   = 0x00000403
  TCKA_CHAR_COLUMNS                = 0x00000404
  TCKA_COLOR                       = 0x00000405
  TCKA_BITS_PER_PIXEL              = 0x00000406
  TCKA_CHAR_SETS                   = 0x00000480
  TCKA_ENCODING_METHODS            = 0x00000481
  TCKA_MIME_TYPES                  = 0x00000482
  TCKA_MECHANISM_TYPE              = 0x00000500
  TCKA_REQUIRED_CMS_ATTRIBUTES     = 0x00000501
  TCKA_DEFAULT_CMS_ATTRIBUTES      = 0x00000502
  TCKA_SUPPORTED_CMS_ATTRIBUTES    = 0x00000503
  TCKA_ALLOWED_MECHANISMS          = 0x40000600
  TCKA_VENDOR_DEFINED              = -2147483648 /* 0x80000000*/
  TCKA_INVALID                     = -1
}

/**
 * 机制类型
 */
enum MechanismType{
  TCKM_RSA_PKCS_KEY_PAIR_GEN             = 0x00000000
  TCKM_RSA_PKCS                          = 0x00000001
  TCKM_RSA_9796                          = 0x00000002
  TCKM_RSA_X_509                         = 0x00000003
  TCKM_MD2_RSA_PKCS                      = 0x00000004
  TCKM_MD5_RSA_PKCS                      = 0x00000005
  TCKM_SHA1_RSA_PKCS                     = 0x00000006
  TCKM_RIPEMD128_RSA_PKCS                = 0x00000007
  TCKM_RIPEMD160_RSA_PKCS                = 0x00000008
  TCKM_RSA_PKCS_OAEP                     = 0x00000009
  TCKM_RSA_X9_31_KEY_PAIR_GEN            = 0x0000000A
  TCKM_RSA_X9_31                         = 0x0000000B
  TCKM_SHA1_RSA_X9_31                    = 0x0000000C
  TCKM_RSA_PKCS_PSS                      = 0x0000000D
  TCKM_SHA1_RSA_PKCS_PSS                 = 0x0000000E
  TCKM_DSA_KEY_PAIR_GEN                  = 0x00000010
  TCKM_DSA                               = 0x00000011
  TCKM_DSA_SHA1                          = 0x00000012
  TCKM_DSA_SHA224                        = 0x00000013
  TCKM_DSA_SHA256                        = 0x00000014
  TCKM_DSA_SHA384                        = 0x00000015
  TCKM_DSA_SHA512                        = 0x00000016
  TCKM_DH_PKCS_KEY_PAIR_GEN              = 0x00000020
  TCKM_DH_PKCS_DERIVE                    = 0x00000021
  TCKM_X9_42_DH_KEY_PAIR_GEN             = 0x00000030
  TCKM_X9_42_DH_DERIVE                   = 0x00000031
  TCKM_X9_42_DH_HYBRID_DERIVE            = 0x00000032
  TCKM_X9_42_MQV_DERIVE                  = 0x00000033
  TCKM_SHA256_RSA_PKCS                   = 0x00000040
  TCKM_SHA384_RSA_PKCS                   = 0x00000041
  TCKM_SHA512_RSA_PKCS                   = 0x00000042
  TCKM_SHA256_RSA_PKCS_PSS               = 0x00000043
  TCKM_SHA384_RSA_PKCS_PSS               = 0x00000044
  TCKM_SHA512_RSA_PKCS_PSS               = 0x00000045
  TCKM_SHA224_RSA_PKCS                   = 0x00000046
  TCKM_SHA224_RSA_PKCS_PSS               = 0x00000047
  TCKM_SHA512_224                        = 0x00000048
  TCKM_SHA512_224_HMAC                   = 0x00000049
  TCKM_SHA512_224_HMAC_GENERAL           = 0x0000004A
  TCKM_SHA512_224_KEY_DERIVATION         = 0x0000004B
  TCKM_SHA512_256                        = 0x0000004C
  TCKM_SHA512_256_HMAC                   = 0x0000004D
  TCKM_SHA512_256_HMAC_GENERAL           = 0x0000004E
  TCKM_SHA512_256_KEY_DERIVATION         = 0x0000004F
  TCKM_SHA512_T                          = 0x00000050
  TCKM_SHA512_T_HMAC                     = 0x00000051
  TCKM_SHA512_T_HMAC_GENERAL             = 0x00000052
  TCKM_SHA512_T_KEY_DERIVATION           = 0x00000053
  TCKM_RC2_KEY_GEN                       = 0x00000100
  TCKM_RC2_ECB                           = 0x00000101
  TCKM_RC2_CBC                           = 0x00000102
  TCKM_RC2_MAC                           = 0x00000103
  TCKM_RC2_MAC_GENERAL                   = 0x00000104
  TCKM_RC2_CBC_PAD                       = 0x00000105
  TCKM_RC4_KEY_GEN                       = 0x00000110
  TCKM_RC4                               = 0x00000111
  TCKM_DES_KEY_GEN                       = 0x00000120
  TCKM_DES_ECB                           = 0x00000121
  TCKM_DES_CBC                           = 0x00000122
  TCKM_DES_MAC                           = 0x00000123
  TCKM_DES_MAC_GENERAL                   = 0x00000124
  TCKM_DES_CBC_PAD                       = 0x00000125
  TCKM_DES2_KEY_GEN                      = 0x00000130
  TCKM_DES3_KEY_GEN                      = 0x00000131
  TCKM_DES3_ECB                          = 0x00000132
  TCKM_DES3_CBC                          = 0x00000133
  TCKM_DES3_MAC                          = 0x00000134
  TCKM_DES3_MAC_GENERAL                  = 0x00000135
  TCKM_DES3_CBC_PAD                      = 0x00000136
  TCKM_DES3_CMAC_GENERAL                 = 0x00000137
  TCKM_DES3_CMAC                         = 0x00000138
  TCKM_CDMF_KEY_GEN                      = 0x00000140
  TCKM_CDMF_ECB                          = 0x00000141
  TCKM_CDMF_CBC                          = 0x00000142
  TCKM_CDMF_MAC                          = 0x00000143
  TCKM_CDMF_MAC_GENERAL                  = 0x00000144
  TCKM_CDMF_CBC_PAD                      = 0x00000145
  TCKM_DES_OFB64                         = 0x00000150
  TCKM_DES_OFB8                          = 0x00000151
  TCKM_DES_CFB64                         = 0x00000152
  TCKM_DES_CFB8                          = 0x00000153
  TCKM_MD2                               = 0x00000200
  TCKM_MD2_HMAC                          = 0x00000201
  TCKM_MD2_HMAC_GENERAL                  = 0x00000202
  TCKM_MD5                               = 0x00000210
  TCKM_MD5_HMAC                          = 0x00000211
  TCKM_MD5_HMAC_GENERAL                  = 0x00000212
  TCKM_SHA_1                             = 0x00000220
  TCKM_SHA_1_HMAC                        = 0x00000221
  TCKM_SHA_1_HMAC_GENERAL                = 0x00000222
  TCKM_RIPEMD128                         = 0x00000230
  TCKM_RIPEMD128_HMAC                    = 0x00000231
  TCKM_RIPEMD128_HMAC_GENERAL            = 0x00000232
  TCKM_RIPEMD160                         = 0x00000240
  TCKM_RIPEMD160_HMAC                    = 0x00000241
  TCKM_RIPEMD160_HMAC_GENERAL            = 0x00000242
  TCKM_SHA256                            = 0x00000250
  TCKM_SHA256_HMAC                       = 0x00000251
  TCKM_SHA256_HMAC_GENERAL               = 0x00000252
  TCKM_SHA224                            = 0x00000255
  TCKM_SHA224_HMAC                       = 0x00000256
  TCKM_SHA224_HMAC_GENERAL               = 0x00000257
  TCKM_SHA384                            = 0x00000260
  TCKM_SHA384_HMAC                       = 0x00000261
  TCKM_SHA384_HMAC_GENERAL               = 0x00000262
  TCKM_SHA512                            = 0x00000270
  TCKM_SHA512_HMAC                       = 0x00000271
  TCKM_SHA512_HMAC_GENERAL               = 0x00000272
  TCKM_SECURID_KEY_GEN                   = 0x00000280
  TCKM_SECURID                           = 0x00000282
  TCKM_HOTP_KEY_GEN                      = 0x00000290
  TCKM_HOTP                              = 0x00000291
  TCKM_ACTI                              = 0x000002A0
  TCKM_ACTI_KEY_GEN                      = 0x000002A1
  TCKM_CAST_KEY_GEN                      = 0x00000300
  TCKM_CAST_ECB                          = 0x00000301
  TCKM_CAST_CBC                          = 0x00000302
  TCKM_CAST_MAC                          = 0x00000303
  TCKM_CAST_MAC_GENERAL                  = 0x00000304
  TCKM_CAST_CBC_PAD                      = 0x00000305
  TCKM_CAST3_KEY_GEN                     = 0x00000310
  TCKM_CAST3_ECB                         = 0x00000311
  TCKM_CAST3_CBC                         = 0x00000312
  TCKM_CAST3_MAC                         = 0x00000313
  TCKM_CAST3_MAC_GENERAL                 = 0x00000314
  TCKM_CAST3_CBC_PAD                     = 0x00000315
  /* Note that CAST128 and CAST5 are the same algorim */
  TCKM_CAST5_KEY_GEN                     = 0x00000320
#   TCKM_CAST128_KEY_GEN                   = 0x00000320
  TCKM_CAST5_ECB                         = 0x00000321
#   TCKM_CAST128_ECB                       = 0x00000321
  TCKM_CAST128_CBC                       = 0x00000322
  TCKM_CAST128_MAC                       = 0x00000323
  TCKM_CAST128_MAC_GENERAL               = 0x00000324
  TCKM_CAST128_CBC_PAD                   = 0x00000325
  TCKM_RC5_KEY_GEN                       = 0x00000330
  TCKM_RC5_ECB                           = 0x00000331
  TCKM_RC5_CBC                           = 0x00000332
  TCKM_RC5_MAC                           = 0x00000333
  TCKM_RC5_MAC_GENERAL                   = 0x00000334
  TCKM_RC5_CBC_PAD                       = 0x00000335
  TCKM_IDEA_KEY_GEN                      = 0x00000340
  TCKM_IDEA_ECB                          = 0x00000341
  TCKM_IDEA_CBC                          = 0x00000342
  TCKM_IDEA_MAC                          = 0x00000343
  TCKM_IDEA_MAC_GENERAL                  = 0x00000344
  TCKM_IDEA_CBC_PAD                      = 0x00000345
  TCKM_GENERIC_SECRET_KEY_GEN            = 0x00000350
  TCKM_CONCATENATE_BASE_AND_KEY          = 0x00000360
  TCKM_CONCATENATE_BASE_AND_DATA         = 0x00000362
  TCKM_CONCATENATE_DATA_AND_BASE         = 0x00000363
  TCKM_XOR_BASE_AND_DATA                 = 0x00000364
  TCKM_EXTRACT_KEY_FROM_KEY              = 0x00000365
  TCKM_SSL3_PRE_MASTER_KEY_GEN           = 0x00000370
  TCKM_SSL3_MASTER_KEY_DERIVE            = 0x00000371
  TCKM_SSL3_KEY_AND_MAC_DERIVE           = 0x00000372
  TCKM_SSL3_MASTER_KEY_DERIVE_DH         = 0x00000373
  TCKM_TLS_PRE_MASTER_KEY_GEN            = 0x00000374
  TCKM_TLS_MASTER_KEY_DERIVE             = 0x00000375
  TCKM_TLS_KEY_AND_MAC_DERIVE            = 0x00000376
  TCKM_TLS_MASTER_KEY_DERIVE_DH          = 0x00000377
  TCKM_TLS_PRF                           = 0x00000378
  TCKM_SSL3_MD5_MAC                      = 0x00000380
  TCKM_SSL3_SHA1_MAC                     = 0x00000381
  TCKM_MD5_KEY_DERIVATION                = 0x00000390
  TCKM_MD2_KEY_DERIVATION                = 0x00000391
  TCKM_SHA1_KEY_DERIVATION               = 0x00000392
  TCKM_SHA256_KEY_DERIVATION             = 0x00000393
  TCKM_SHA384_KEY_DERIVATION             = 0x00000394
  TCKM_SHA512_KEY_DERIVATION             = 0x00000395
  TCKM_SHA224_KEY_DERIVATION             = 0x00000396
  TCKM_PBE_MD2_DES_CBC                   = 0x000003A0
  TCKM_PBE_MD5_DES_CBC                   = 0x000003A1
  TCKM_PBE_MD5_CAST_CBC                  = 0x000003A2
  TCKM_PBE_MD5_CAST3_CBC                 = 0x000003A3
  TCKM_PBE_MD5_CAST128_CBC               = 0x000003A4
  TCKM_PBE_SHA1_CAST128_CBC              = 0x000003A5
  TCKM_PBE_SHA1_RC4_128                  = 0x000003A6
  TCKM_PBE_SHA1_RC4_40                   = 0x000003A7
  TCKM_PBE_SHA1_DES3_EDE_CBC             = 0x000003A8
  TCKM_PBE_SHA1_DES2_EDE_CBC             = 0x000003A9
  TCKM_PBE_SHA1_RC2_128_CBC              = 0x000003AA
  TCKM_PBE_SHA1_RC2_40_CBC               = 0x000003AB
  TCKM_PKCS5_PBKD2                       = 0x000003B0
  TCKM_PBA_SHA1_WITH_SHA1_HMAC           = 0x000003C0
  TCKM_WTLS_PRE_MASTER_KEY_GEN           = 0x000003D0
  TCKM_WTLS_MASTER_KEY_DERIVE            = 0x000003D1
  TCKM_WTLS_MASTER_KEY_DERIVE_DH_ECC     = 0x000003D2
  TCKM_WTLS_PRF                          = 0x000003D3
  TCKM_WTLS_SERVER_KEY_AND_MAC_DERIVE    = 0x000003D4
  TCKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE    = 0x000003D5
  TCKM_TLS10_MAC_SERVER                  = 0x000003D6
  TCKM_TLS10_MAC_CLIENT                  = 0x000003D7
  TCKM_TLS12_MAC                         = 0x000003D8
  TCKM_TLS12_KDF                         = 0x000003D9
  TCKM_TLS12_MASTER_KEY_DERIVE           = 0x000003E0
  TCKM_TLS12_KEY_AND_MAC_DERIVE          = 0x000003E1
  TCKM_TLS12_MASTER_KEY_DERIVE_DH        = 0x000003E2
  TCKM_TLS12_KEY_SAFE_DERIVE             = 0x000003E3
  TCKM_TLS_MAC                           = 0x000003E4
  TCKM_TLS_KDF                           = 0x000003E5
  TCKM_KEY_WRAP_LYNKS                    = 0x00000400
  TCKM_KEY_WRAP_SET_OAEP                 = 0x00000401
  TCKM_CMS_SIG                           = 0x00000500
  TCKM_KIP_DERIVE                        = 0x00000510
  TCKM_KIP_WRAP                          = 0x00000511
  TCKM_KIP_MAC                           = 0x00000512
  TCKM_CAMELLIA_KEY_GEN                  = 0x00000550
  TCKM_CAMELLIA_ECB                      = 0x00000551
  TCKM_CAMELLIA_CBC                      = 0x00000552
  TCKM_CAMELLIA_MAC                      = 0x00000553
  TCKM_CAMELLIA_MAC_GENERAL              = 0x00000554
  TCKM_CAMELLIA_CBC_PAD                  = 0x00000555
  TCKM_CAMELLIA_ECB_ENCRYPT_DATA         = 0x00000556
  TCKM_CAMELLIA_CBC_ENCRYPT_DATA         = 0x00000557
  TCKM_CAMELLIA_CTR                      = 0x00000558
  TCKM_ARIA_KEY_GEN                      = 0x00000560
  TCKM_ARIA_ECB                          = 0x00000561
  TCKM_ARIA_CBC                          = 0x00000562
  TCKM_ARIA_MAC                          = 0x00000563
  TCKM_ARIA_MAC_GENERAL                  = 0x00000564
  TCKM_ARIA_CBC_PAD                      = 0x00000565
  TCKM_ARIA_ECB_ENCRYPT_DATA             = 0x00000566
  TCKM_ARIA_CBC_ENCRYPT_DATA             = 0x00000567
  TCKM_SEED_KEY_GEN                      = 0x00000650
  TCKM_SEED_ECB                          = 0x00000651
  TCKM_SEED_CBC                          = 0x00000652
  TCKM_SEED_MAC                          = 0x00000653
  TCKM_SEED_MAC_GENERAL                  = 0x00000654
  TCKM_SEED_CBC_PAD                      = 0x00000655
  TCKM_SEED_ECB_ENCRYPT_DATA             = 0x00000656
  TCKM_SEED_CBC_ENCRYPT_DATA             = 0x00000657
  TCKM_SKIPJACK_KEY_GEN                  = 0x00001000
  TCKM_SKIPJACK_ECB64                    = 0x00001001
  TCKM_SKIPJACK_CBC64                    = 0x00001002
  TCKM_SKIPJACK_OFB64                    = 0x00001003
  TCKM_SKIPJACK_CFB64                    = 0x00001004
  TCKM_SKIPJACK_CFB32                    = 0x00001005
  TCKM_SKIPJACK_CFB16                    = 0x00001006
  TCKM_SKIPJACK_CFB8                     = 0x00001007
  TCKM_SKIPJACK_WRAP                     = 0x00001008
  TCKM_SKIPJACK_PRIVATE_WRAP             = 0x00001009
  TCKM_SKIPJACK_RELAYX                   = 0x0000100a
  TCKM_KEA_KEY_PAIR_GEN                  = 0x00001010
  TCKM_KEA_KEY_DERIVE                    = 0x00001011
  TCKM_KEA_DERIVE                        = 0x00001012
  TCKM_FORTEZZA_TIMESTAMP                = 0x00001020
  TCKM_BATON_KEY_GEN                     = 0x00001030
  TCKM_BATON_ECB128                      = 0x00001031
  TCKM_BATON_ECB96                       = 0x00001032
  TCKM_BATON_CBC128                      = 0x00001033
  TCKM_BATON_COUNTER                     = 0x00001034
  TCKM_BATON_SHUFFLE                     = 0x00001035
  TCKM_BATON_WRAP                        = 0x00001036
  TCKM_EC_KEY_PAIR_GEN                   = 0x00001040
  TCKM_ECDSA                             = 0x00001041
  TCKM_ECDSA_SHA1                        = 0x00001042
  TCKM_ECDSA_SHA224                      = 0x00001043
  TCKM_ECDSA_SHA256                      = 0x00001044
  TCKM_ECDSA_SHA384                      = 0x00001045
  TCKM_ECDSA_SHA512                      = 0x00001046
  TCKM_ECDH1_DERIVE                      = 0x00001050
  TCKM_ECDH1_COFACTOR_DERIVE             = 0x00001051
  TCKM_ECMQV_DERIVE                      = 0x00001052
  TCKM_ECDH_AES_KEY_WRAP                 = 0x00001053
  TCKM_RSA_AES_KEY_WRAP                  = 0x00001054
  TCKM_JUNIPER_KEY_GEN                   = 0x00001060
  TCKM_JUNIPER_ECB128                    = 0x00001061
  TCKM_JUNIPER_CBC128                    = 0x00001062
  TCKM_JUNIPER_COUNTER                   = 0x00001063
  TCKM_JUNIPER_SHUFFLE                   = 0x00001064
  TCKM_JUNIPER_WRAP                      = 0x00001065
  TCKM_FASTHASH                          = 0x00001070
  TCKM_AES_KEY_GEN                       = 0x00001080
  TCKM_AES_ECB                           = 0x00001081
  TCKM_AES_CBC                           = 0x00001082
  TCKM_AES_MAC                           = 0x00001083
  TCKM_AES_MAC_GENERAL                   = 0x00001084
  TCKM_AES_CBC_PAD                       = 0x00001085
  TCKM_AES_CTR                           = 0x00001086
  TCKM_AES_GCM                           = 0x00001087
  TCKM_AES_CCM                           = 0x00001088
  TCKM_AES_CTS                           = 0x00001089
  TCKM_AES_CMAC                          = 0x0000108A
  TCKM_AES_CMAC_GENERAL                  = 0x0000108B
  TCKM_AES_XCBC_MAC                      = 0x0000108C
  TCKM_AES_XCBC_MAC_96                   = 0x0000108D
  TCKM_AES_GMAC                          = 0x0000108E
  TCKM_BLOWFISH_KEY_GEN                  = 0x00001090
  TCKM_BLOWFISH_CBC                      = 0x00001091
  TCKM_TWOFISH_KEY_GEN                   = 0x00001092
  TCKM_TWOFISH_CBC                       = 0x00001093
  TCKM_BLOWFISH_CBC_PAD                  = 0x00001094
  TCKM_TWOFISH_CBC_PAD                   = 0x00001095
  TCKM_DES_ECB_ENCRYPT_DATA              = 0x00001100
  TCKM_DES_CBC_ENCRYPT_DATA              = 0x00001101
  TCKM_DES3_ECB_ENCRYPT_DATA             = 0x00001102
  TCKM_DES3_CBC_ENCRYPT_DATA             = 0x00001103
  TCKM_AES_ECB_ENCRYPT_DATA              = 0x00001104
  TCKM_AES_CBC_ENCRYPT_DATA              = 0x00001105
  TCKM_GOSTR3410_KEY_PAIR_GEN            = 0x00001200
  TCKM_GOSTR3410                         = 0x00001201
  TCKM_GOSTR3410_WITH_GOSTR3411          = 0x00001202
  TCKM_GOSTR3410_KEY_WRAP                = 0x00001203
  TCKM_GOSTR3410_DERIVE                  = 0x00001204
  TCKM_GOSTR3411                         = 0x00001210
  TCKM_GOSTR3411_HMAC                    = 0x00001211
  TCKM_GOST28147_KEY_GEN                 = 0x00001220
  TCKM_GOST28147_ECB                     = 0x00001221
  TCKM_GOST28147                         = 0x00001222
  TCKM_GOST28147_MAC                     = 0x00001223
  TCKM_GOST28147_KEY_WRAP                = 0x00001224
  TCKM_DSA_PARAMETER_GEN                 = 0x00002000
  TCKM_DH_PKCS_PARAMETER_GEN             = 0x00002001
  TCKM_X9_42_DH_PARAMETER_GEN            = 0x00002002
  TCKM_DSA_PROBABLISTIC_PARAMETER_GEN    = 0x00002003
  TCKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN    = 0x00002004
  TCKM_AES_OFB                           = 0x00002104
  TCKM_AES_CFB64                         = 0x00002105
  TCKM_AES_CFB8                          = 0x00002106
  TCKM_AES_CFB128                        = 0x00002107
  TCKM_AES_CFB1                          = 0x00002108
  TCKM_AES_KEY_WRAP                      = 0x00002109     /* WAS: = 0x00001090 */
  TCKM_AES_KEY_WRAP_PAD                  = 0x0000210A     /* WAS: = 0x00001091 */
  TCKM_RSA_PKCS_TPM_1_1                  = 0x00004001
  TCKM_RSA_PKCS_OAEP_TPM_1_1             = 0x00004002
  TCKM_VENDOR_DEFINED                    = -2147483648 /* 0x80000000 */

  /* 格尔自定义机制 */
  TCKM_RSA_RAW                           = -2147475456 /* 0x80002000 */
  TCKM_SM1_CBC                           = -2147483637 /* 0x8000000B */
  TCKM_SM1_CBC_PAD                       = -2147483626 /* 0x80000016 */
  TCKM_SM1_ECB                           = -2147483638 /* 0x8000000A */
  TCKM_SM1_ECB_PAD                       = -2147479548 /* 0x80001004 */
  TCKM_SM1_KEY_GEN                       = -2147483633 /* 0x8000000F */
  TCKM_SM2                               = -2147450880 /* 0x80008000 */
  TCKM_SM2_ENC_KEY_PAIR_GEN              = -2147450878 /* 0x80008002 */
  TCKM_SM2_KEY_PAIR_GEN                  = -2147450879 /* 0x80008001 */
  TCKM_SM2_RAW                           = -2147450368 /* 0x80008200 */
  TCKM_SM2_SIGN                          = -2147450620 /* 0x80008104 */
  TCKM_SM3                               = -2147483643 /* 0x80000005 */
  TCKM_SM3_HASH                          = -2147483642 /* 0x80000006 */
  TCKM_SM3_SM2                           = -2147450624 /* 0x80008100 */
  TCKM_SM3_SM2_DER                       = -2147450623 /* 0x80008101 */
  TCKM_SM4                               = -2147442688 /* 0x8000A000 */
  TCKM_SM4_CBC                           = -2147483383 /* 0x80000109 */
  TCKM_SM4_CBC_PAD                       = -2147483380 /* 0x8000010C */
  TCKM_SM4_ECB                           = -2147483384 /* 0x80000108 */
  TCKM_SM4_ECB_PAD                       = -2147442431 /* 0x8000A101 */
  TCKM_SM4_GCM                           = -2147483377 /* 0x8000010F */
  TCKM_SM4_KEY_GEN                       = -2147483385 /* 0x80000107 */
  TCKM_INVALID                           = -1
}

/**
 * 用户类型
 */
enum UserType {
  TCKU_SO                                = 0x00000000
  TCKU_USER                              = 0x00000001
  TCKU_CONTEXT_SPECIFIC                  = 0x00000002
  TCKU_INVALID                           = -1
}

/**
 * 返回值
 */
enum Rv {
  TCKR_OK                                = 0x00000000
  TCKR_CANCEL                            = 0x00000001
  TCKR_HOST_MEMORY                       = 0x00000002
  TCKR_SLOT_ID_INVALID                   = 0x00000003
  TCKR_GENERAL_ERROR                     = 0x00000005
  TCKR_FUNCTION_FAILED                   = 0x00000006
  TCKR_ARGUMENTS_BAD                     = 0x00000007
  TCKR_NO_EVENT                          = 0x00000008
  TCKR_NEED_TO_CREATE_THREADS            = 0x00000009
  TCKR_CANT_LOCK                         = 0x0000000A
  TCKR_ATTRIBUTE_READ_ONLY               = 0x00000010
  TCKR_ATTRIBUTE_SENSITIVE               = 0x00000011
  TCKR_ATTRIBUTE_TYPE_INVALID            = 0x00000012
  TCKR_ATTRIBUTE_VALUE_INVALID           = 0x00000013
  TCKR_ACTION_PROHIBITED                 = 0x0000001B
  TCKR_DATA_INVALID                      = 0x00000020
  TCKR_DATA_LEN_RANGE                    = 0x00000021
  TCKR_DEVICE_ERROR                      = 0x00000030
  TCKR_DEVICE_MEMORY                     = 0x00000031
  TCKR_DEVICE_REMOVED                    = 0x00000032
  TCKR_ENCRYPTED_DATA_INVALID            = 0x00000040
  TCKR_ENCRYPTED_DATA_LEN_RANGE          = 0x00000041
  TCKR_FUNCTION_CANCELED                 = 0x00000050
  TCKR_FUNCTION_NOT_PARALLEL             = 0x00000051
  TCKR_FUNCTION_NOT_SUPPORTED            = 0x00000054
  TCKR_KEY_HANDLE_INVALID                = 0x00000060
  TCKR_KEY_SIZE_RANGE                    = 0x00000062
  TCKR_KEY_TYPE_INCONSISTENT             = 0x00000063
  TCKR_KEY_NOT_NEEDED                    = 0x00000064
  TCKR_KEY_CHANGED                       = 0x00000065
  TCKR_KEY_NEEDED                        = 0x00000066
  TCKR_KEY_INDIGESTIBLE                  = 0x00000067
  TCKR_KEY_FUNCTION_NOT_PERMITTED        = 0x00000068
  TCKR_KEY_NOT_WRAPPABLE                 = 0x00000069
  TCKR_KEY_UNEXTRACTABLE                 = 0x0000006A
  TCKR_MECHANISM_INVALID                 = 0x00000070
  TCKR_MECHANISM_PARAM_INVALID           = 0x00000071
  TCKR_OBJECT_HANDLE_INVALID             = 0x00000082
  TCKR_OPERATION_ACTIVE                  = 0x00000090
  TCKR_OPERATION_NOT_INITIALIZED         = 0x00000091
  TCKR_PIN_INCORRECT                     = 0x000000A0
  TCKR_PIN_INVALID                       = 0x000000A1
  TCKR_PIN_LEN_RANGE                     = 0x000000A2
  TCKR_PIN_EXPIRED                       = 0x000000A3
  TCKR_PIN_LOCKED                        = 0x000000A4
  TCKR_SESSION_CLOSED                    = 0x000000B0
  TCKR_SESSION_COUNT                     = 0x000000B1
  TCKR_SESSION_HANDLE_INVALID            = 0x000000B3
  TCKR_SESSION_PARALLEL_NOT_SUPPORTED    = 0x000000B4
  TCKR_SESSION_READ_ONLY                 = 0x000000B5
  TCKR_SESSION_EXISTS                    = 0x000000B6
  TCKR_SESSION_READ_ONLY_EXISTS          = 0x000000B7
  TCKR_SESSION_READ_WRITE_SO_EXISTS      = 0x000000B8
  TCKR_SIGNATURE_INVALID                 = 0x000000C0
  TCKR_SIGNATURE_LEN_RANGE               = 0x000000C1
  TCKR_TEMPLATE_INCOMPLETE               = 0x000000D0
  TCKR_TEMPLATE_INCONSISTENT             = 0x000000D1
  TCKR_TOKEN_NOT_PRESENT                 = 0x000000E0
  TCKR_TOKEN_NOT_RECOGNIZED              = 0x000000E1
  TCKR_TOKEN_WRITE_PROTECTED             = 0x000000E2
  TCKR_UNWRAPPING_KEY_HANDLE_INVALID     = 0x000000F0
  TCKR_UNWRAPPING_KEY_SIZE_RANGE         = 0x000000F1
  TCKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  = 0x000000F2
  TCKR_USER_ALREADY_LOGGED_IN            = 0x00000100
  TCKR_USER_NOT_LOGGED_IN                = 0x00000101
  TCKR_USER_PIN_NOT_INITIALIZED          = 0x00000102
  TCKR_USER_TYPE_INVALID                 = 0x00000103
  TCKR_USER_ANOTHER_ALREADY_LOGGED_IN    = 0x00000104
  TCKR_USER_TOO_MANY_TYPES               = 0x00000105
  TCKR_WRAPPED_KEY_INVALID               = 0x00000110
  TCKR_WRAPPED_KEY_LEN_RANGE             = 0x00000112
  TCKR_WRAPPING_KEY_HANDLE_INVALID       = 0x00000113
  TCKR_WRAPPING_KEY_SIZE_RANGE           = 0x00000114
  TCKR_WRAPPING_KEY_TYPE_INCONSISTENT    = 0x00000115
  TCKR_RANDOM_SEED_NOT_SUPPORTED         = 0x00000120
  TCKR_RANDOM_NO_RNG                     = 0x00000121
  TCKR_DOMAIN_PARAMS_INVALID             = 0x00000130
  TCKR_CURVE_NOT_SUPPORTED               = 0x00000140
  TCKR_BUFFER_TOO_SMALL                  = 0x00000150
  TCKR_SAVED_STATE_INVALID               = 0x00000160
  TCKR_INFORMATION_SENSITIVE             = 0x00000170
  TCKR_STATE_UNSAVEABLE                  = 0x00000180
  TCKR_CRYPTOKI_NOT_INITIALIZED          = 0x00000190
  TCKR_CRYPTOKI_ALREADY_INITIALIZED      = 0x00000191
  TCKR_MUTEX_BAD                         = 0x000001A0
  TCKR_MUTEX_NOT_LOCKED                  = 0x000001A1
  TCKR_NEW_PIN_MODE                      = 0x000001B0
  TCKR_NEXT_OTP                          = 0x000001B1
  TCKR_EXCEEDED_MAX_ITERATIONS           = 0x000001B5
  TCKR_FIPS_SELF_TEST_FAILED             = 0x000001B6
  TCKR_LIBRARY_LOAD_FAILED               = 0x000001B7
  TCKR_PIN_TOO_WEAK                      = 0x000001B8
  TCKR_PUBLIC_KEY_INVALID                = 0x000001B9
  TCKR_FUNCTION_REJECTED                 = 0x00000200
  TCKR_VENDOR_DEFINED                    = -2147483648 /* 0x80000000*/
  TCKR_INVALID                           = -1
}

/**
 * 版本号
 */
struct Version {
  1: i8  u8Major
  2: i8  u8Minor
}

/**
 * 接口信息
 */
struct Info {
  1: Version  cryptokiVersion
  2: string   manufacturerID
  3: i32      flags                /* must be zero */
  4: string   libraryDescription
  5: Version  libraryVersion
}

/* Slot info flags */
const i32 TCKF_TOKEN_PRESENT     = 0x00000001  /* a token is there */
const i32 TCKF_REMOVABLE_DEVICE  = 0x00000002  /* removable devices*/
const i32 TCKF_HW_SLOT           = 0x00000004  /* hardware slot */

/**
 * 槽位信息
 */
struct SlotInfo {
  1: string   slotDescription
  2: string   manufacturerID
  3: i32      flags
  4: Version  hardwareVersion
  5: Version  firmwareVersion
}

/* Token info flags */
const i32 TCKF_RNG                            = 0x00000001
const i32 TCKF_WRITE_PROTECTED                = 0x00000002
const i32 TCKF_LOGIN_REQUIRED                 = 0x00000004
const i32 TCKF_USER_PIN_INITIALIZED           = 0x00000008
const i32 TCKF_RESTORE_KEY_NOT_NEEDED         = 0x00000020
const i32 TCKF_CLOCK_ON_TOKEN                 = 0x00000040
const i32 TCKF_PROTECTED_AUTHENTICATION_PATH  = 0x00000100
const i32 TCKF_DUAL_CRYPTO_OPERATIONS         = 0x00000200
const i32 TCKF_TOKEN_INITIALIZED              = 0x00000400
const i32 TCKF_SECONDARY_AUTHENTICATION       = 0x00000800
const i32 TCKF_USER_PIN_COUNT_LOW             = 0x00010000
const i32 TCKF_USER_PIN_FINAL_TRY             = 0x00020000
const i32 TCKF_USER_PIN_LOCKED                = 0x00040000
const i32 TCKF_USER_PIN_TO_BE_CHANGED         = 0x00080000
const i32 TCKF_SO_PIN_COUNT_LOW               = 0x00100000
const i32 TCKF_SO_PIN_FINAL_TRY               = 0x00200000
const i32 TCKF_SO_PIN_LOCKED                  = 0x00400000
const i32 TCKF_SO_PIN_TO_BE_CHANGED           = 0x00800000
const i32 TCKF_ERROR_STATE                    = 0x01000000

/**
 * 令牌信息
 */
struct TokenInfo {
  1: string    label
  2: string    manufacturerID
  3: string    model
  4: string    serialNumber
  5: i32       flags
  6: i32       ulMaxSessionCount
  7: i32       ulSessionCount
  8: i32       ulMaxRwSessionCount
  9: i32       ulRwSessionCount
  10: i32      ulMaxPinLen
  11: i32      ulMinPinLen
  12: i32      ulTotalPublicMemory
  13: i32      ulFreePublicMemory
  14: i32      ulTotalPrivateMemory
  15: i32      ulFreePrivateMemory
  16: Version  hardwareVersion
  17: Version  firmwareVersion
  18: string   utcTime
}


/* Mechanism info flags */
const i32 TCKF_HW                 = 0x00000001
const i32 TCKF_ENCRYPT            = 0x00000100
const i32 TCKF_DECRYPT            = 0x00000200
const i32 TCKF_DIGEST             = 0x00000400
const i32 TCKF_SIGN               = 0x00000800
const i32 TCKF_SIGN_RECOVER       = 0x00001000
const i32 TCKF_VERIFY             = 0x00002000
const i32 TCKF_VERIFY_RECOVER     = 0x00004000
const i32 TCKF_GENERATE           = 0x00008000
const i32 TCKF_GENERATE_KEY_PAIR  = 0x00010000
const i32 TCKF_WRAP               = 0x00020000
const i32 TCKF_UNWRAP             = 0x00040000
const i32 TCKF_DERIVE             = 0x00080000

/**
 * 机制信息
 */
struct MechanismInfo {
  1: i32  ulMinKeySize
  2: i32  ulMaxKeySize
  3: i32  flags
}

/* Session info states */
const i32 TCKS_RO_PUBLIC_SESSION   = 0
const i32 TCKS_RO_USER_FUNCTIONS   = 1
const i32 TCKS_RW_PUBLIC_SESSION   = 2
const i32 TCKS_RW_USER_FUNCTIONS   = 3
const i32 TCKS_RW_SO_FUNCTIONS     = 4

/* Session info flags */
const i32 TCKF_RW_SESSION          = 0x00000002 /* session is r/w */
const i32 TCKF_SERIAL_SESSION      = 0x00000004 /* no parallel    */

/**
 * 会话信息
 */
struct SessionInfo {
  1: i32    slotID
  2: i32    state
  3: i32    flags
  4: i32    ulDeviceError
}

/**
 * 属性对象，支持下列关键属性
 * i32类型属性值为-1，binary类型属性值为空时表示无效
 * bool类型的属性用i8表示, 取值如下:
 * 1:真 0:假 -1:无效
 */
struct Attribute {
  1:  i32           CLASS                = -1
  2:  i32           KEY_TYPE             = -1
  3:  binary        LABEL
  4:  binary        ID
  5:  i8            LOCAL                = -1
  6:  i8            TOKEN                = -1
  7:  i8            PRIVATE              = -1
  8:  i8            ENCRYPT              = -1
  9:  i8            DECRYPT              = -1
  10: i8            DERIVE               = -1
  11: i8            MODIFIABLE           = -1
  12: i8            DESTROYABLE          = -1
  13: i8            SIGN                 = -1
  14: i8            SIGN_RECOVER         = -1
  15: i8            VERIFY               = -1
  16: i8            VERIFY_RECOVER       = -1
  17: i8            WRAP                 = -1
  18: i8            UNWRAP               = -1
  19: i8            SENSITIVE            = -1
  20: i8            ALWAYS_SENSITIVE     = -1
  21: i8            EXTRACTABLE          = -1
  22: i8            NEVER_EXTRACTABLE    = -1
  23: binary        MODULUS
  24: i32           MODULUS_BITS         = -1
  25: binary        PRIME_1
  26: binary        PRIME_2
  27: binary        COEFFICIENT
  28: binary        EXPONENT_1
  29: binary        EXPONENT_2
  30: binary        PRIVATE_EXPONENT
  31: binary        PUBLIC_EXPONENT
  32: binary        EC_PARAMS
  33: binary        EC_POINT
  34: binary        VALUE
  35: i32           VALUE_LEN            = -1
  36: binary        CHECK_VALUE
}

/**
 * RSA OAEP/PSS MGF1哈希方法
 */
enum MGF {
  TCKG_MGF1_SHA1         = 0x00000001
  TCKG_MGF1_SHA256       = 0x00000002
  TCKG_MGF1_SHA384       = 0x00000003
  TCKG_MGF1_SHA512       = 0x00000004
  TCKG_MGF1_SHA224       = 0x00000005
  TCKG_MGF1_INVALID      = -1
}

/**
 * RSA OAEP编码源类型
 */
enum OAEPSourceType {
  TCKZ_DATA_SPECIFIED    = 0x00000001
  TCKZ_DATA_INVALID      = -1
}

/**
 * RSA-OAEP机制参数
 */
struct OAEPParameter {
  1: MechanismType      hashAlg  = -1
  2: MGF                mgf      = -1
  3: OAEPSourceType     source   = -1
  4: binary             data
}

/**
 * RSA-PSS机制参数
 */
struct PSSParameter {
  1: MechanismType      hashAlg  = -1
  2: MGF                mgf      = -1
  3: i32                sLen     = 0
}

/**
 * GCM加密模式机制参数
 */
struct GCMParameter {
  1: binary             iv
  2: binary             aad
  3: i32                tagBits  = -1
  4: i32                ivBits   = -1
}

/**
 * 默认机制参数
 */
struct DefaultParameter {
  1: binary             parameter
}


/**
 * 机制参数类型
 */
enum ParameterType {
  NONE     = 0
  DEFAULT  = 1
  GCM      = 2
  OAEP     = 3
  PSS      = 4
}

/**
 * 机制参数
 */
struct Parameter {
  1: required ParameterType       type                = 0
  2: optional DefaultParameter    defaultParameter
  3: optional GCMParameter        gcmParameter
  4: optional OAEPParameter       oaepParameter
  5: optional PSSParameter        pssParameter
}

/**
 * 机制，通过机制类型与机制参数传递不同类型参数
 */
struct Mechanism {
  1: required MechanismType  mechanism
  2: optional Parameter      parameter
}

/**
 * 密钥
 */
struct Object {
  1: bool isLMK  = false
  2: bool isEncryptedWithLMK = false
  3: binary value
  4: Attribute attribute
}

/**
 * 密钥对
 */
struct KeyPair {
  1: Object  publicKey
  2: Object  privateKey
}

/**
 * PKCS#11接口数据操作类型
 */
enum Operation {
  /** 正常操作 */
  NORMAL      = 0
  /** 仅获取数据处理后长度 */
  GET_LENGTH  = 1
}


/**
 * 对数据增加一个长度值，主要用于客户端调用传空指针的情况
 * 根据数据Operation, 当使用NORMAL操作时, 返回加密/签名/摘要处理后数据
 * 当使用GET_LENGTH操作时, 服务端仅返回加密/签名/摘要后数据长度, data为空
 * 附加和保留字段用于CBC/GCM等特定算法还需要返回IV/TAG等值的情况
 */
struct Data {
  1: binary             data
  2: i32                dataLen
  3: optional binary    extra
  4: optional binary    reserved
}

/**
 *  PKCS#11异常
 */
exception P11Exception {
  1: string  err
  2: i32     errCode
}
