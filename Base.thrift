// 密码机服务的接口定义

// 命名空间
namespace cpp svc.base
namespace java kl.hsm.server.svc.base

include "p11.thrift"
///////////////////////////////////////////////////////////////
// 常量定义

const i32 ver_base = 1   // 服务版本

// 非对称密钥算法标识
const i32 RSA                  = 0x00010000
const i32 SM2                  = 0x00020100
const i32 ECDSA                = 0x00080000
const i32 EdDSA                = 0x00200100

// 非对称密钥曲线参数
const i32 ECDSA_P          = 0x00080001
const i32 ECDSA_SECTK1      = 0x00080002
const i32 ECDSA_SECTR1      = 0x00080003
const i32 ECDSA_BrainpoolR1    = 0x00080004
const i32 ECDSA_BrainpoolT1    = 0x00080005
const i32 EdDSA_Ed25519        = 1

// 对称密码算法标识
const i32 SMS4_ECB             = 0x00000401
const i32 SMS4_CBC             = 0x00000402
const i32 SMS4_CFB             = 0x00000404
const i32 SMS4_OFB             = 0x00000408
const i32 SMS4_GCM             = 0x00000440
const i32 SMS4_CCM             = 0x000004A0

const i32 AES_ECB              = 0x00002001
const i32 AES_CBC              = 0x00002002
const i32 AES_CFB              = 0x00002004
const i32 AES_OFB              = 0x00002008
const i32 AES_GCM              = 0x00002040
const i32 AES_CCM              = 0x000020A0

// 杂凑算法标识
const i32 SM3                  = 0x00000001
const i32 SHA1                 = 0x00000002
const i32 SHA256               = 0x00000004
const i32 SHA512               = 0x00000008
const i32 SHA384               = 0x00000010
const i32 SHA224               = 0x00000020
const i32 SHA3_256             = 0x00001004
const i32 SHA3_512             = 0x00001008
const i32 SHA3_384             = 0x00001010
const i32 SHA3_224             = 0x00001020
const i32 AES_CMAC             = 0x000020c0;


// EdDSA 签名模式区分标志
// Ed25519 原文签名
const i32 ED25519_FLAG             = 0x01
// Ed25519ph 模式签名
const i32 ED25519PH_FLAG           = 0x02
// Ed25519ctx 模式签名
const i32 ED25519CTX_FLAG          = 0x03


///////////////////////////////////////////////////////////////
// 异常定义
///////////////////////////////////////////////////////////////

// HSM服务端异常
exception SvcException {
  1: required string  err        // 错误信息，服务方错误时必须填写
  2: optional i32     errCode    // 错误码， 可选
}

///////////////////////////////////////////////////////////////
// 输入结构和枚举类型定义
///////////////////////////////////////////////////////////////

// 算法标识
enum Algo {
    // 国密
    SM1 = 1
    SM2 = 2
    SM3 = 3
    SM4 = 4
    SM7 = 7 //暂未实现
    SM9 = 9
    ZUC = 10

    // 国际对称
    DES = 20
    TriDES = 21
    RC4 = 22 //暂未实现
    AES_128 = 23
    AES_256 = 24
    AES_192 = 25

    // 国际非对称
    RSA_1024 = 30
    RSA_2048 = 32
    RSA_3072 = 34
    RSA_4096 = 33

    ECC_256 = 36 //暂未实现
    ECC_384 = 37 //暂未实现
    SECP256k1 = 39

    // 国际hash
    MD5 = 40
    SHA1 = 41
    SHA2_256 = 42
    SHA2_384 = 43
    SHA2_512 = 44
    SHA2_224 = 45

    BRAINPOOLP256T1 = 51
    BRAINPOOLP256R1 = 52
    Ed25519 = 53
    ECDSA = 54
    Ed25519ph = 55
    Ed25519ctx = 56

    PRIME256v1 = 38
    SECP384r1 = 57
    SECP521r1 = 258

    SECT233K1 = 266
    SECT283K1 = 267
    SECT409K1 = 268
    SECT571K1 = 269

    SECT233R1 = 271
    SECT283R1 = 272
    SECT409R1 = 273
    SECT571R1 = 274

    BRAINPOOLP224T1 = 276
    BRAINPOOLP320T1 = 277
    BRAINPOOLP384T1 = 278
    BRAINPOOLP512T1 = 279

    BRAINPOOLP224R1 = 286
    BRAINPOOLP320R1 = 287
    BRAINPOOLP384R1 = 288
    BRAINPOOLP512R1 = 289
}


// 对称加密模式
enum EncMode {
    ECB = 1
    CBC = 2
    OFB = 3
    CFB = 4
    GCM = 5
    CTR = 6
    CCM = 7
}

// 补位方式
enum Padding {
  NoPadding = 1
  PKCS5Padding = 2
  PKCS7Padding = 3
  PBOCPadding = 4
}

// RSA补位方式
enum RsaPadding {
  NoPadding = 0
  PKCS1_5 = 1
  OAEP_SHA1 = 2
  OAEP_SHA256 = 3
  PSS = 6
}

// key标识
enum KeyIdentifier {
  INDEX = 1
  LABEL = 2
}

// ibc算法用户私钥类型
enum Sm9UserPriKeyType {
  ENCRYPT = 1
  SIGN = 2
  EXCHANGE = 3
}

// 方法
enum Action {
  GenerateP10 = 1
}

// 对称加密参数
struct SymParam {
    1: EncMode mode                             // 对称加密模式，如ECB、CBC等，参考EncMode定义
    2: binary  iv                               // 初始化向量， 除ECB外其他都需要
    3: Padding padding = Padding.PKCS7Padding   // padding 模式，NoPadding时要保证数据长度满足加密算法
    4: binary aad                               //gcm模式选择参数,用作完整性检查
    5: i32  tagbits                             //gcm tag的长度
}

// 摘要算法参数
struct HashAlgoParam {
  1: required Algo hashAlgo  // 摘要算法
  2: optional string salt    // 国密 sm3需要，缺省为 1234567812345678
  3: optional binary pubKey  // 国密 sm3需要
}

///////////////////////////////////////////////////////////////
// 输出结构定义
///////////////////////////////////////////////////////////////

// 非对称key返回
struct AsymKeypair {
  1: binary pubKey           // 公钥
  2: binary privKey          // 私钥
}

// int和binary返回
struct IntBinary {
  1: i32 intvalue             // 整型
  2: binary binvalue          // 二进制型
}



// 响应方密钥协商参数返回
struct keyAgreementResp {
  1: bool ok                  // 是否成功
  2: string error             // 错误信息
  3: binary pubKey            // 响应方公钥
  4: binary spTmpPubKey       // 响应方临时公钥
  5: i64 sKeyHandle           // 会话密钥句柄
}

// 密钥对数字信封结构（保护的是密钥对，其中私钥是数字信封保护的）(根据0016-SKF标准SKF_ENVELOPEDKEYBLOG设计)
struct EnvelopedKeyPair {
  1: i64 symAlg             // 对称算法标识，应为SM4
  2: i64 bits               // 受保护密钥对的长度，SM2为256
  3: binary privKey_cipher  // 受保护密钥对私钥密文。若key_cipher为空，则本参数为私钥明文
  4: binary pubKey          // 受保护密钥对公钥明文
  5: binary key_cipher      // 用保护公钥加密的对称密钥密文。该对称密钥用来解密私钥密文。若该变量为空，则表明privKey_cipher就是私钥明文。
}

// 非对称key返回
struct SM9Encapsulate {
  1: binary key            // 密钥
  2: binary cipher         // 封装密文结果
}

struct SM9KeyExchange{
  1: i32 sKeyHandle       // 会话密钥句柄
  2: binary spTmpPubKey   // 响应方临时公钥
  3: binary hashSA        //验证使用
  4: binary hashSB        //验证使用
}

// keyIndex
struct KeyIndexParam {
  1: i32 index          // 秘钥索引
  2: i32 type           // 1 对称 2 非对称
}

struct KeyIndexResponse {
  1: i32 index          // 秘钥索引
  2: i32 type           // 1 对称 2 非对称
  3: binary hash        // 摘要值
}
struct EcDsaRefPublicKey {
  1: i32 bits
  2: i32 curveType
  3: binary x
  4: binary y
}

struct EdDsaRefPrivateKey {
  1: i32 bits
  2: i32 curveType
  3: binary k
}

struct EdDsaRefPublicKey {
  1: i32 bits
  2: i32 curveType
  3: binary a
}

struct EcDsaRefPrivateKey {
  1: i32 bits
  2: i32 curveType
  3: binary d
}

struct RsaRefPublicKey {
  1: i32 bits
  2: binary m
  3: binary e
}

struct RsaRefPrivateKey {
  1: i32 bits
  2: binary m
  3: binary e
  4: binary d
  5: binary prime
  6: binary pexP
  7: binary coeF
}


struct EccRefPublicKey {
  1:i32 bits
  2:binary x
  3:binary y
}

struct EccRefPrivateKey {
  1: i32  bits
  2: binary k
}

struct EdDsaKeyPair {
  1: EdDsaRefPublicKey pubKey
  2: EdDsaRefPrivateKey priKey
}

struct EcDsaKeyPair {
  1: EcDsaRefPublicKey pubKey
  2: EcDsaRefPrivateKey priKey
}

struct KeyPairWithKek{
  1: i64 handler
  2: binary pubKey
  3: binary priKey
  4: binary pucTagData
}

struct EncryptData {
  1: binary encData // 加密后的密文
  2: binary tag // 校验值，根据选择的加密模式，可能为空
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                      SM9新增数据结构
//////////////////////////////////////////////////////////////////////////////////////////////////////

struct SM9SignMasterKeyPair{
  1: binary privateKey    // 签名主私钥32字节
  2: binary publicKey     // 签名主私钥(xa,xb,ya,yb)128字节
  3: binary pairG         // 加速参数
}

struct SM9EncMasterKeyPair{
  1: binary privateKey    // 加密主私钥32字节
  2: binary publicKey     // 加密主私钥(x,y)64字节
  3: binary pairG         // 加速参数
}

struct SM9MasterKey{
  1: SM9SignMasterKeyPair sign  // 签名主密钥对
  2: SM9EncMasterKeyPair  enc   // 加密主密钥对
}
///////////////////////////////////////////////////////////////
// 管控接口Struct
///////////////////////////////////////////////////////////////
// sm2 KeyBasic
struct AsymmetricKeyBasic{
    1: i32 startIndex
    2: i32 endIndex
    3: i32 reservePos
}

// sm4 KeyBasic
struct SymmetricKeyBasic{
    1: i32 startIndex
    2: i32 endIndex
    3: i32 reservePos
}

///////////////////////////////////////////////////////////////
// 无状态接口相关定义
///////////////////////////////////////////////////////////////
struct KeyPairWithKekStateless{
    1: binary handler
    2: binary pubKey
    3: binary priKey
    4: binary pucTagData
}

struct IntBinaryStateless {
  1: binary handler           // LMK密文
  2: binary key               // 索引密文
}

// 非对称key返回
struct AsymKeypairStateless {
    1: binary pubKey           // 公钥
    2: binary privKey          // 私钥
    3: Algo algo               // 密钥类型
}

struct SslKey {
    1: binary clientHashKey     // 客户端杂凑密钥
    2: binary serverHashKey     // 服务端杂凑密钥
    3: binary clientEncKey      // 客户端数据加密密钥
    4: binary serverEncKey      // 服务端数据加密密钥
    5: binary clientIv          // 客户端IV
    6: binary serverIv          // 服务端IV
}

///////////////////////////////////////////////////////////////
// 服务接口定义
///////////////////////////////////////////////////////////////

/**
 * 密码机基础功能服务
 *
 * 函数命名规则： 如果一个函数以In结尾，表明其使用的是密码机内部的密钥
 */
service SvcBase {

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                      设备管理类
  //////////////////////////////////////////////////////////////////////////////////////////////////////
  /**
   * 获取服务版本（后续升级使用）
   *
   * @param 无
   * @return 服务端版本的字符串。
   */
  string getVersion()

  /**
   * 获取密码机所有内部密钥的hash值，用于确认密码机密钥复制的结果。
   *
   * @param 无
   * @return 内部密钥的32字节hash值，算法为SM3。
   */
  binary getKeyHash()

  /**
   * 在加密机内部创建Session，该Session与连接无关，在连接断线后继续存在，客户端重连后能直接使用Session ID进行操作。
   *
   * @param 无
   * @return Session ID。
   */
  i64 openSession() throws (1: SvcException ex)

  /**
   * 关闭session
   *
   * @param sessionId OpenSession返回的Session ID
   * @return 无
   */
  void closeSession(1: i64 sessionId ) throws (1: SvcException ex)

  /**
   * 获取私钥使用权限
   *
   * @param sessionId OpenSession返回的Session ID。
   * @param keyIndex 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @param password 加密机内部非对称密钥对应的密码，只有密码正确才能获取操作权限。
   * @return 无。
   */
  void getPrivateKeyAccessRight(1: i64 sessionId, 2: i32 keyIndex, 3: binary password ) throws (1: SvcException ex)

  /**
   * 释放私钥使用权限
   *
   * @param sessionId OpenSession返回的Session ID。
   * @param keyIndex 加密机内部非对称密钥索引。
   * @return 无。
   */
  void releasePrivateKeyAccessRight(1: i64 sessionId, 2: i32 keyIndex ) throws (1: SvcException ex)




  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                      基本密码运算类
  //////////////////////////////////////////////////////////////////////////////////////////////////////

  /**
   * 产生随机数
   *
   * @param len 随机数的字节数。
   * @return 随机数。
   */
  binary getRandom(1: i32 len) throws (1: SvcException ex)

  ///////////////////////////////////////////////////
  // 对称运算
  ///////////////////////////////////////////////////

  /** 外部密钥对称加密
   *
   * @param algo 对称加密算法。
   * @param key 对称加密密钥，注意长度需与算法匹配。
   * @param param 对称加密参数。
   * @param data 待加密数据。
   * @return 密文。
   */
  binary enc(1: Algo algo, 2: binary key, 3: SymParam param, 4: binary data) throws (1: SvcException ex)

  /** 内部密钥对称加密
   *
   * @param keyID 加密机内部对称密钥索引。使用时注意其对应算法。
   * @param param 对称加密参数。
   * @param data 待加密数据。
   * @return 密文。
   */
  binary encIn(1: i32 keyID, 2: SymParam param, 3: binary data) throws (1: SvcException ex)

  /** 外部密钥对称解密
   *
   * @param algo 对称加密算法。
   * @param key 对称加密密钥，注意长度需与算法匹配。
   * @param param 对称加密参数。
   * @param data 密文数据。
   * @return 明文。
   */
  binary dec(1: Algo algo, 2: binary key, 3: SymParam param, 4: binary data) throws (1: SvcException ex)
  /** 内部密钥对称解密
   *
   * @param keyID 加密机内部对称密钥索引。使用时注意其对应算法。
   * @param param 对称加密参数。
   * @param data 密文。
   * @return 明文。
   */
  binary decIn(1: i32 keyID, 2: SymParam param, 3: binary data) throws (1: SvcException ex)

  ///////////////////////////////////////////////////
  // 非对称运算
  ///////////////////////////////////////////////////

  /** 生成非对称密钥并导出
   *
   * @param algo 非对称算法。
   * @return 密钥对。
   */
  AsymKeypair asymGenKeyExp(1: Algo algo) throws (1: SvcException ex)

  /** 导出内部加密公钥
   *
   * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @return 内部加密公钥。
   */
  binary asymKeyExpEncPub(1: i32 keyID) throws (1: SvcException ex)

  /** 导出内部签名公钥
   *
   * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @return 内部签名公钥。
   */
  binary asymKeyExpSignPub(1: i32 keyID) throws (1: SvcException ex)

  /** 使用外部私钥签名
   *
   * @param algo 非对称加密算法。
   * @param privKey 外部私钥，注意与算法匹配。
   * @param digest 待签名数据的摘要值。
   * @param hashParam 计算摘要时使用的参数。
   * @return 签名结果。
   */
  binary sign(1: Algo algo, 2: binary privKey, 3: binary digest, 4: HashAlgoParam hashParam) throws (1: SvcException ex)

  /** 使用内部私钥签名
   *
   * @param sessionId OpenSession返回的Session ID。
   * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @param algo 非对称加密算法。
   * @param digest 待签名数据的摘要值。
   * @param hashParam 计算摘要时使用的参数。
   * @return 签名结果。
   */
  binary signIn(1:i64 sessionId, 2: i32 keyID, 3: binary digest, 4: HashAlgoParam hashParam) throws (1: SvcException ex)

  /** 使用外部公钥验签
   *
   * @param algo 非对称加密算法。
   * @param pubKey 外部公钥，注意与算法匹配。
   * @param digest 待签名数据的摘要值。
   * @param hashParam 计算摘要时使用的参数。
   * @param signData 签名结果。
   * @return 是否验签通过。
   */
  bool verify(1: Algo algo, 2: binary pubKey, 3: binary digest, 4: HashAlgoParam hashParam, 5: binary signData) throws (1: SvcException ex)

  /** 使用内部公钥验签
   *
   * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @param digest 待签名数据的摘要值。
   * @param hashParam 计算摘要时使用的参数。
   * @param signData 签名结果。
   * @return 是否验签通过。
   */
  bool verifyIn(1: i32 keyID, 2: binary digest, 3: HashAlgoParam hashParam, 4: binary signData) throws (1: SvcException ex)

  /** 使用外部公钥加密
   *
   * @param algo 非对称加密算法。
   * @param pubKey 外部公钥，注意与算法匹配。
   * @param data 待加密数据。
   * @return 密文。
   */
  binary asymEnc(1: Algo algo, 2: binary pubKey, 3: binary data) throws (1: SvcException ex)

  /** 使用内部公钥加密
   *
   * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @param data 待加密数据。
   * @return 密文。
   */
  binary asymEncIn(1: i32 keyID, 2: binary data) throws (1: SvcException ex)

  /** 使用外部私钥解密
   *
   * @param algo 非对称加密算法。
   * @param privKey 外部私钥，注意与算法匹配。
   * @param data 待加密数据。
   * @return 密文。
   */
  binary asymDec(1: Algo algo, 2: binary privKey, 3: binary data) throws (1: SvcException ex)

  /** 使用内部私钥解密
   *
   * @param sessionId OpenSession返回的Session ID。
   * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @param data 待加密数据。
   * @return 密文。
   */
  binary asymDecIn(1:i64 sessionId, 2:i32 keyID, 3:binary data) throws (1: SvcException ex)



  /** 内部公钥运算
   * 主要用于内部RSA公钥运算。
   * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @param data 待运算数据。
   * @param withEncKey 是否使用加密密钥对运算。是：使用加密密钥对；否：使用签名密钥对
   * @return 公钥运算结果。
   */
  binary asymPubOpIn(1: i32 keyID, 2: binary data, 3: bool withEncKey) throws (1: SvcException ex)

  /** 使用内部私钥运算
   * 主要用于内部RSA私钥运算
   * @param sessionId OpenSession返回的Session ID。
   * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @param data 待加密数据。
   * @param withEncKey 是否使用加密密钥对运算。是：使用加密密钥对；否：使用签名密钥对
   * @return 密文。
   */
  binary asymPrivOpIn(1:i64 sessionId, 2:i32 keyID, 3:binary data, 4: bool withEncKey) throws (1: SvcException ex)
  ///////////////////////////////////////////////////
  // 摘要/哈希/杂凑
  ///////////////////////////////////////////////////

  /** 摘要
   * @param data: 待摘要数据
   * @param param: 算法参数
   * @return 摘要值。
   */
  binary hash(1: binary data, 2:HashAlgoParam param) throws (1: SvcException ex)

  /** 计算MAC
   * @param sessionId: Session ID
   * @param sKeyHandle：会话密钥句柄
   * @param algo: 算法
   * @param data：数据
   * @param iv: 初始向量
   * @return 消息鉴别码。
   */
  binary mac(1:i64 sessionId,2:i32 sKeyHandle, 3:Algo algo, 4:binary data, 5:binary iv) throws (1: SvcException ex)

  /** 计算MAC
   * @param sessionId: Session ID
   * @param sKeyHandle：会话密钥句柄
   * @param algo: 算法
   * @param data：数据
   * @param iv: 初始向量
   * @param mode: 使用对称加密模式
   * @return 消息鉴别码。
   */
  binary macByMode(1:i64 sessionId,2:i32 sKeyHandle, 3:Algo algo, 4:binary data, 5:SymParam param) throws (1: SvcException ex)

  /** 使用外部密钥计算MAC
   * @param key: 密钥
   * @param algo: 算法
   * @param data: 数据
   * @param iv: 初始向量
   * @return 消息鉴别码。
   */
  binary macEx(1:binary key, 2:Algo algo, 3:binary data, 4:binary iv) throws (1:SvcException ex)

  /** 使用外部密钥计算MAC
   * @param key: 密钥
   * @param algo: 算法
   * @param data: 数据
   * @param iv: 初始向量
   * @param mode: 使用对称加密模式
   * @return 消息鉴别码。
   */
  binary macByModeEx(1:binary key, 2:Algo algo, 3:binary data, 4:SymParam param) throws (1:SvcException ex)

  /** 使用内部索引密钥计算MAC
   * @param keyID: 密钥索引
   * @param algo: 算法
   * @param data: 数据
   * @param iv: 初始向量
   * @param mode: 使用对称加密模式
   * @return 消息鉴别码。
   */
  binary macByModeIn(1:i32 keyID, 2:Algo algo, 3:binary data, 4:SymParam param) throws (1:SvcException ex)

  /** 密钥协商外部测试接口
   * @param role: 0 发起方/ 1 接受方
   * @param myId: 本方ID
   * @param myPrivkey: 本方私钥
   * @param myPubkey: 本方公钥
   * @param myTmpPrivkey: 本方临时私钥
   * @param myTmpPubkey: 本方临时公钥
   * @param peerId: 对方ID
   * @param peerPubkey: 对方公钥
   * @param peerTmpPubkey: 对方临时公钥
   * @return 协商出的会话密钥。
   */
  //binary keyAgreementSM2(1:i32 role, 2:string myId, 3:binary myPrivkey, 4:binary myPubkey, 5:binary myTmpPrivkey, 6:binary myTmpPubkey, 7:string peerId, 8:binary peerPubkey, 9:binary peerTmpPubkey) throws (1:SvcException ex)
  binary keyAgreementSM2(1:i32 role, 2:binary myId, 3:binary myPrivkey, 4:binary myPubkey, 5:binary myTmpPrivkey, 6:binary myTmpPubkey, 7:binary peerId, 8:binary peerPubkey, 9:binary peerTmpPubkey) throws (1:SvcException ex)


  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                      会话密钥相关
  //////////////////////////////////////////////////////////////////////////////////////////////////////
  /** 导入明文会话密钥
   * @param sessionId OpenSession返回的Session ID。
   * @param data: 会话密钥明文。
   * @return 会话密钥句柄：sKeyHandle。
   */
  i32 importSKey(1:i64 sessionId, 2:binary data) throws (1: SvcException ex)

  /**  导入ECC（公钥）加密的会话密钥
   * @param sessionId OpenSession返回的Session ID。
   * @param index 加密机内部非对称加密密钥索引。使用时注意其对应算法。
   * @param data: 会话密钥S密文。
   * @return 会话密钥句柄：sKeyHandle。
   */
  i32 importSKeyInA(1:i64 sessionId, 2:i32 index, 3:binary data) throws (1: SvcException ex)

  /**  导入对称密钥KEK加密的会话密钥
   * @param sessionId OpenSession返回的Session ID。
   * @param algID 对称加密算法。
   * @param kekIndex 加密机内部对称密钥索引。使用时注意其对应算法。
   * @param data: 会话密钥密文。
   * @return 会话密钥句柄：sKeyHandle。
   */
  i32 importSKeyInS(1:i64 sessionId, 2:i32 algID, 3:i32 kekIndex, 4:binary data) throws (1: SvcException ex)

  /**  生成以内部公钥加密的会话密钥
   * @param sessionId OpenSession返回的Session ID。
   * @param index 加密机内部对称密钥索引。使用时注意其对应算法。
   * @param keybits 会话密钥位长度。
   * @return 会话密钥，含句柄sKeyHandle、会话密钥密文。
   */
  IntBinary exportGenSKeyInA(1:i64 sessionId, 2:i32 index, 3:i32 keybits) throws (1: SvcException ex)

  /**  生成以外部公钥加密的会话密钥
   * @param sessionId OpenSession返回的Session ID。
   * @param algID 非对称算法。
   * @param pubKey 外部公钥，注意与算法匹配。
   * @param keybits 会话密钥位长度。
   * @return 会话密钥，含句柄sKeyHandle、会话密钥密文。
   */
  IntBinary exportGenSKeyOutA(1:i64 sessionId, 2:i32 algID, 3:binary pubKey, 4:i32 keybits) throws (1: SvcException ex)

  /**  生成以内部KEK加密的会话密钥
   * @param sessionId OpenSession返回的Session ID。
   * @param algID 对称算法。
   * @param index 加密机内部对称密钥索引。使用时注意其对应算法。
   * @param keybits 会话密钥位长度。
   * @return 会话密钥，含句柄sKeyHandle、会话密钥密文。
   */
  IntBinary exportGenSKeyInS(1:i64 sessionId, 2:i32 algID, 3:i32 kekIndex, 4:i32 keybits) throws (1: SvcException ex)

  /**  使用会话密钥加密
   * @param sessionId OpenSession返回的Session ID。
   * @param algo 对称算法。
   * @param sKeyHandle 生成会话密钥输出的句柄。
   * @param param 对称加密参数。
   * @param data 待加密数据。
   * @return 密文。
   */
  binary encSKey(1:i64 sessionId, 2: Algo algo, 3: i32 sKeyHandle, 4: SymParam param, 5: binary data) throws (1: SvcException ex)

  /**  使用会话密钥解密
   * @param sessionId OpenSession返回的Session ID。
   * @param algo 对称算法。
   * @param sKeyHandle 生成会话密钥输出的句柄。
   * @param param 对称加密参数。
   * @param data 密文数据。
   * @return 明文。
   */
  binary decSKey(1:i64 sessionId, 2: Algo algo, 3: i32 sKeyHandle, 4: SymParam param, 5: binary data) throws (1: SvcException ex)

  /**  销毁会话密钥
   * @param sessionId OpenSession返回的Session ID。
   * @param sKeyHandle 生成会话密钥输出的句柄。
   * @return 无。
   */
  void destorySKey(1:i64 sessionId, 2:i32 sKeyHandle) throws (1: SvcException ex)


  /**  生成密钥协商参数并输出（仅支持SM2算法）
   * @param sessionId OpenSession返回的Session ID。
   * @param privKeyIndex 加密机内部非对称密钥索引。
   * @param keyBits 会话密钥位长度。
   * @param spID 本方（协商发起方）ID。
   * @param algo 算法（没有使用）。
   * @return 密钥协商参数。
   */
  //keyAgreementResp initiateAgreementKey(1:i64 sessionId, 2:i32 privKeyIndex, 3:i32 keyBits, 4:string spID, 5: Algo algo) throws (1: SvcException ex)
  keyAgreementResp initiateAgreementKey(1:i64 sessionId, 2:i32 privKeyIndex, 3:i32 keyBits, 4:binary spID, 5: Algo algo) throws (1: SvcException ex)

  /**  计算会话密钥（仅支持SM2算法）
   * @param sessionId OpenSession返回的Session ID。
   * @param respID 协商接收方ID。
   * @param spPubKey 协商发起方公钥。
   * @param spTmpPubKey: 协商发起方临时公钥。
   * @param handle 协商接收方发回的handle数据。
   * @param algo 算法（没有使用）。
   * @return 会话密钥句柄。
   */
  //i64 generateAgreementKey(1:i64 sessionId, 2:string respID, 3:binary spPubKey, 4:binary spTmpPubKey, 5:i32 handle 6: Algo algo) throws (1: SvcException ex)
  i64 generateAgreementKey(1:i64 sessionId, 2:binary respID, 3:binary spPubKey, 4:binary spTmpPubKey, 5:i32 handle 6: Algo algo) throws (1: SvcException ex)

  /**  产生协商数据并计算会话密钥（仅支持SM2算法）
   * @param sessionId OpenSession返回的Session ID。
   * @param privKeyIndex 本方（协商接收方）内部私钥索引。
   * @param keyBits 会话密钥位长度。
   * @param respID 本方（协商接收方）ID。
   * @param spID 对方（协商发起方）ID。
   * @param spPubKey 对方（协商发起方）公钥。
   * @param spTmpPubKey 对方（协商发起方）临时公钥。
   * @param algo 算法（没有使用）。
   * @return 密钥协商参数。
   */
  //keyAgreementResp respondAgreementKey(1:i64 sessionId, 2:i32 privKeyIndex, 3:i32 keyBits, 4:string respID, 5:string spID, 6:binary spPubKey, 7:binary spTmpPubKey, 8: Algo algo) throws (1: SvcException ex)
  keyAgreementResp respondAgreementKey(1:i64 sessionId, 2:i32 privKeyIndex, 3:i32 keyBits, 4:binary respID, 5:binary spID, 6:binary spPubKey, 7:binary spTmpPubKey, 8: Algo algo) throws (1: SvcException ex)

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                      数字信封
  //////////////////////////////////////////////////////////////////////////////////////////////////////

  /**  SDF转加密：原使用内部公钥加密，转为外部公钥加密输出
   * @param sessionId OpenSession返回的Session ID。
   * @param privKeyIndex 内部非对称索引。
   * @param algID 外部公钥算法。
   * @param pubKey 外部公钥。
   * @param data 密文。
   * @return 转加密后的密文。
   */
  binary exchangeEnvelope(1:i64 sessionId, 2:i32 index, 3: i32 algID, 4:binary pubKey, 5:binary data) throws (1: SvcException ex)

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                      文件操作类
  //////////////////////////////////////////////////////////////////////////////////////////////////////

  // 文件操作
  //   创建文件
  /**  创建文件
   * @param fileName 待创建的文件名。
   * @param fileSize 文件容量。
   * @return 无。
   */
  void createFile(1:string fileName,2:i32 fileSize) throws (1: SvcException ex)

  /**  读取文件
   * @param fileName 文件名。
   * @param offSet 字节偏移量。
   * @return 无。
   */
  IntBinary readFile(1:string fileName,2:i32 offSet, 3:i32 readLength) throws (1: SvcException ex)

  /**  写文件
   * @param fileName 文件名。
   * @param offSet 字节偏移量。
   * @param data 写入数据。
   * @param writeLength 写入长度。
   * @return 无。
   */
  void writeFile(1:string fileName,2:i32 offSet,3:binary data,4:i32 writeLength) throws (1: SvcException ex)

  /**  删除文件
   * @param fileName 文件名。
   * @return 无。
   */
  void deleteFile(1:string fileName) throws (1: SvcException ex)

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                      扩展接口
  //////////////////////////////////////////////////////////////////////////////////////////////////////

  /** 导入密钥对（网关所需接口）,该接口打破了业务接口不进行密钥管理的设定。根本原因是国密标准相互矛盾。
   *  @param sessionId: OpenSession返回的Session ID。
   *  @param index: 导入密钥对所在的索引。
   *  @param withEncKey: 是否操作加密密钥对，true-加密密钥对, false-签名密钥对
   *  @param envelopedKeyPair: 传入密钥对。其私钥可为明文，若为密文，则是本索引另一对密钥对公钥数字信封保护。
   */
  void importKeyPair(1:i64 sessionId, 2:i32 index, 3:bool withEncKey, 4:EnvelopedKeyPair envelopedKeyPair) throws (1: SvcException ex)

  /** 祖冲之算法(EEA)接口，加密解密(调用一次加密，调用两次解密)
   *  @param inbuf:输入数据
   *  @param key:密钥
   *  @param count
   *  @param bearer <32
   *  @param direction 1位
   *  @return 返回EEA计算后的结果
   */
  binary zuc_eea(1:binary inbuf, 2:binary key, 3:i32 count, 4:i32 bearer, 5:i32 direction) throws (1: SvcException ex)

  /** 祖冲之算法(EIA)接口，计算MAC
   *  @param inbuf:输入原文
   *  @param key:密钥
   *  @param count
   *  @param bearer <32
   *  @param direction 1位
   *  @return 返回EIA计算后的结果
   */
  binary zuc_eia(1:binary inbuf, 2:binary key, 3:i32 count, 4:i32 bearer, 5:i32 direction) throws (1: SvcException ex)


  /**  主动刷新sessionId，避免被定时销毁
   *  @param sessionId:需要刷新的SessionID。
   *
   */
  void updateSessionId(1:i64 sessionId) throws (1: SvcException ex)

  /** 获取设备证书，此接口仅适用于格尔烟草密码机
   * @param c      国家
   * @param st     州/省
   * @param l      市
   * @param oArea  县
   * @param ouArea 区/本地域名
   * @param cn     组织机构
   */
  binary getDeviceCert(1:string c,2:string st,3:string l,4:string oArea,5:string ouArea,6:string cn,7:i32 index,8:i64 sessionId) throws(1:SvcException ex)

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                      SM9接口
  //////////////////////////////////////////////////////////////////////////////////////////////////////

  /** SM9算法，导出主公钥
   *  @param uiSM9Index:S在密码机中SM9索引号
   *  @param type:用户功能类型:1-加解密,2-加签验签
   *  @return 返回SM9主公钥
   */
  binary sm9ExportMasterPublicKey(1:i32 uiSM9Index, 2:i32 type) throws (1: SvcException ex)

  /** SM9算法生成用户私钥
   *  @param sm9Index:密码机中SM9索引号
   *  @param userID:用户ID
   *  @param type:用户功能类型:1-加解密,2-加签验签,3-秘钥协商
   *  @return 返回SM9主公钥
   */
  binary sm9GenerateUserPrivKey(1:i32 sm9Index, 2:binary userID, 3:i32 type) throws (1: SvcException ex)

  /**
   * sm9 加密
   *
   * @param data            加密数据
   * @param id              用户 ID，相当于用户公钥
   * @param masterPublicKey 加密主公钥
   * @param type            加密明文的方法：0 基于KDF的序列 ，1 结合KDF的分组
   * @param algo            type为1时,分组加密对称算法(SM4)
   * @return
   * @throws SvcException
   */
  binary sm9Encrypt(binary data, binary id, binary masterPublicKey, i32 type, Algo algo) throws (1: SvcException ex)

  /**
   * sm9 解密
   *
   * @param data       解密数据
   * @param id         用户 ID，相当于用户公钥
   * @param privatekey 私钥
   * @param masterPublicKey 加密主公钥
   * @param type       加密明文的方法：0 基于KDF的序列 ，1 结合KDF的分组
   * @param algo       type为1时,分组加密对称算法(SM4)
   * @return
   * @throws SvcException
   */
  binary sm9Decrypt(binary data, binary id, binary privatekey, i32 type, Algo algo) throws (1: SvcException ex)

  /**
   * sm9 签名
   *
   * @param data            签名数据
   * @param privatekey      私钥
   * @param masterPublicKey 签名主公钥
   * @return
   * @throws SvcException
   */
  binary sm9Sign(binary data, binary privatekey, binary masterPublicKey) throws (1: SvcException ex)

  /**
   * sm9 验签
   *
   * @param data            签名数据
   * @param id              用户 ID，相当于用户公钥
   * @param signature       签名结果
   * @param masterPublicKey 签名主公钥
   * @return
   * @throws SvcException
   */
  bool sm9Verify(binary data, binary id, binary signature, binary masterPublicKey) throws (1: SvcException ex)

  /**
   * SM9 密钥封装
   *
   * @param id               用户 ID，相当于用户公钥
   * @param masterPublicKey  加密主公钥
   * @param keyLen           封装密钥长度
   * @return                 秘钥、密文
   * @throws SvcException
   */
  SM9Encapsulate sm9Encap(binary id, binary masterPublicKey, i32 keyLen) throws (1: SvcException ex)

  /**
   * SM9 密钥解封装
   *
   * @param id              用户 ID，相当于用户公钥
   * @param privatekey      用户加密私钥
   * @param cipher          封装密钥结果
   * @param keyLen          封装密钥长度
   * @return                秘钥
   * @throws SvcException
   */
  binary sm9Decap(binary id,binary privatekey, binary cipher,i32 keyLen) throws (1: SvcException ex)

  /**
   * SM9 生成密钥协商参数
   *
   * @param sessionId       会话ID
   * @param responseID      响应方 ID
   * @param masterPublicKey 加密主公钥
   * @return                密钥协商参数句柄、临时公钥
   * @throws SvcException
   */
  IntBinary sm9GenerateAgreementData(i64 sessionId,binary responseID,binary masterPublicKey) throws (1: SvcException ex)


  /**
   * SM9 密钥协商响应方计算会话密钥
   *
   * @param sessionId             会话ID
   * @param keyLen                协商后要求输出的密钥长度
   * @param responseID            响应方 ID
   * @param sponseID              发起方 ID
   * @param privateKey            响应方的用户加密私钥
   * @param masterPublicKey       加密主公钥
   * @param sponsorTmpPublicKey   发起方临时加密主公钥
   * @return                      密钥协商句柄、临时公钥、(HashSA、HashSB)验证使用
   * @throws SvcException
   */
  SM9KeyExchange sm9GenerateAgreemetDataAndKey(i64 sessionId,i32 keyLen, binary responseID, binary sponseID, binary privateKey, binary masterPublicKey, binary sponsorTmpPublicKey) throws (1: SvcException ex)


  /**
   * SM9 密钥协商发起方计算协商密钥并验证
   *
   * @param sessionId             会话ID
   * @param keyLen                协商后要求输出的密钥长度
   * @param sponseID              发起方 ID
   * @param responseID            响应方 ID
   * @param privateKey            响应方的用户加密私钥
   * @param masterPublicKey       加密主公钥
   * @param responseTmpPublicKey  响应方临时加密主公钥
   * @param agreementHandle       协商参数句柄
   * @param hashSA                验证杂凑值
   * @param hashSB                验证杂凑值
   * @return                      密钥协商句柄、(HashSA、HashSB)验证使用
   * @throws SvcException
   */
  SM9KeyExchange sm9GenerateKey(i64 sessionId,i32 keyLen, binary sponseID, binary responseID, binary privateKey, binary masterPublicKey, binary responseTmpPublicKey,i32 agreementHandle, binary hashSA, binary hashSB)throws (1: SvcException ex)

  /**
   * SM9 密钥协商响应方验证协商密钥参数
   *
   * @param sessionId             会话ID
   * @param hashSA                验证杂凑值
   * @param hashSB                验证杂凑值
   * @param sKeyHandle            会话秘钥句柄
   * @return
   * @throws SvcException
   */
  bool sm9GenerateKeyVerify(i64 sessionId, binary hashSA, binary hashSB,i32 sKeyHandle)throws (1: SvcException ex)


  /**
   * 获取对应索引的密钥hash值
   *
   * @param param
   * @return
   * @throws SvcException
   */
  list<KeyIndexResponse> getKeyHashByIndex(1:list<KeyIndexParam>  param)throws (1: SvcException ex)

  /*
   * 生成Ed密钥对明文
   */
  EdDsaKeyPair generateKeyPairEdDsa(
      1: i64 hSessionHandle,          // 加密机sessionId
      2: i32 uiAlgID,                 // 指定算法标识，仅支持 SGD_EdDSA
      3: i32 uiKeyBits,               // 指定密钥长度，仅支持 256
      4: i32 uiCurveType              // 指定曲线参数类型，仅支持 1
    ) throws (1: SvcException ex)

  /*
   * 生成Ec密钥对明文
   */
  EcDsaKeyPair generateKeyPairEcDsa(
      1: i64 hSessionHandle,          // 加密机sessionId
      2: i32 uiAlgID,                 // 指定算法标识，仅支持 SGD_ECDSA
      3: i32 uiKeyBits,               // 指定密钥长度
      4: i32 uiCurveType              // 椭圆曲线参数
    ) throws (1: SvcException ex)

  /*
   * 生成非对称会话密钥
   */
  KeyPairWithKek generateKeypairWithKek(
      1: i64 hSessionHandle,          // 加密机sessionId
      2: i32 uiKEKAlgID,              // 加密机对称密算法类型
      3: i32 uiKEKIndex,              // 加密机对称密钥索引
      4: binary pucIV,                // 初始化向量值（CBC、GCM、CCM 算法时不能为空）
      5: binary pucAAD,               // ADD值（非GCM和CCM算法可不传）
      6: i32 uiAsymAlgID,             // 非对称密钥类型
      7: i32 uiKeyBits,               // 非对称密钥长度
      8: i32 uiCurveType              // 曲线类型
    ) throws (1: SvcException ex)

  /*
   * Ec类型非对称会话密钥签名接口
   * (针对SM2和Ec曲线两类密钥)
   */
  binary signSessionKey(
      1: i64 hSessionHandle,          // 加密机sessionId
      2: i64 keyHandle,          // 会话密钥导入后密钥句柄
      3: binary pucData               // 待签名数据
    ) throws (1: SvcException ex)

  /*
   * 非对称会话密钥签名（针对Ed25519，实现Ed25519\Ed25519ph\Ed25519ctx多种算法）
   */
  binary signEdSessionKey(
      1: i64 hSessionHandle,          // 加密机sessionId
      2: i64 keyHandle,               // 会话密钥导入后密钥句柄
      3: i32 uiFlag,                  // 签名模式区分标志
      4: binary pucContext,           // 缓冲区指针，ED25519ctx 与 ED25519ph特有，最长为 255 字节
      5: binary pucData               // 待签名数据
    ) throws (1: SvcException ex)

  /*
   * RSA 非对称会话密钥签名
   */
  binary signRsaSessionKey (
      1: i64 hSessionHandle,          // 加密机sessionId
      2: i64 keyHandle,               // 会话密钥导入后密钥句柄
      3: i32 uiHashAlg,               // 摘要算法标识
      4: i32 uiPadMode,               // 补位模式 RSA_PKCS1_PSS_PADDING和RSA_PKCS1_PADDING
      5: binary pucData               // 待签名密文
    ) throws (1: SvcException ex)

  /*
   * Ec类型非对称会话密钥签名验证接口
   * (针对SM2和Ec曲线两类密钥)
   */
  bool verifySessionKey(
      1: i64 hSessionHandle,          // 加密机sessionId
      2: i64 keyHandle,               // 会话密钥导入后密钥句柄
      3: binary pucData,              // 原文数据
      4: binary pucSignData           // 签名数据
    ) throws (1: SvcException ex)

  /*
   * 非对称会话密钥签名验证（针对Ed25519，实现Ed25519\Ed25519ph\Ed25519ctx多种算法）
   */
  bool verifyEdSessionKey(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i64 keyHandle,                   // 会话密钥导入后密钥句柄
      3: i32 uiFlag,                      // 签名模式区分标志
      4: binary pucContext,               // 缓冲区指针，ED25519ctx 与 ED25519ph特有，最长为 255 字节
      5: binary pucData,                  // 待签名数据
      6: binary pucSignData               // 签名数据
    ) throws (1: SvcException ex)

  /*
   * RSA 非对称会话密钥签名验证
   */
  bool verifyRsaSessionKey (
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i64 keyHandle,                   // 会话密钥导入后密钥句柄
      3: i32 uiHashAlg,                   // 摘要算法标识
      4: i32 uiPadMode,                   // 补位模式 RSA_PKCS1_PSS_PADDING和RSA_PKCS1_PADDING
      5: binary pucData,                  // 待签名密文
      6: binary pucSignData               // 签名数据
    ) throws (1: SvcException ex)

  /*
   * 非对称会话密钥加密（Ec类型）
   */
  binary encryptSessionKeypair(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i64 keyHandle,                   // 会话密钥导入后密钥句柄
      3: binary pucData                   // 数据原文
    ) throws (1: SvcException ex)

  /*
   * 非对称会话密钥解密（Ec类型）
   */
  binary decryptSessionKeypair(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i64 keyHandle,                   // 会话密钥导入后密钥句柄
      3: binary pucEncData                // 数据密文
    ) throws (1: SvcException ex)

  /*
   * 非对称会话密钥加密（RSA类型）
   */
  binary encryptRsaSessionKeypair(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i64 keyHandle,                   // 会话密钥导入后密钥句柄
      3: i32 uiPadMode,                   // 补位模式（1:RSA_NO_PADDING/2:RSA_PKCS1_PADDING/3:RSA_PKCS1_OAEP_PADDING)
      4: binary pucData                   // 数据明文
    ) throws (1: SvcException ex)

  /*
   * 非对称会话密钥解密（RSA类型）
   */
  binary decryptRsaSessionKeypair(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i64 keyHandle,                   // 会话密钥导入后密钥句柄
      3: i32 uiPadMode,                   // 补位模式（1:RSA_NO_PADDING/2:RSA_PKCS1_PADDING/3:RSA_PKCS1_OAEP_PADDING)
      4: binary pucEncData                // 数据密文
    ) throws (1: SvcException ex)

  /*
   * 对称会话密钥加密
   */
  EncryptData encryptSymmetric(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i64 hKeyHandle,                  // 会话密钥导入后密钥句柄
      3: i32 uiAlgID,                     // 算法标识 (GCM/CCM)
      4: binary pucIV,                    // 缓冲区指针，用于存放输入的 IV 数据
      5: binary pucAAD,                   // 认证数据
      6: binary pucData                   // 待加密数据
    ) throws (1: SvcException ex)

  /*
   * 对称会话密钥解密
   */
  binary decryptSymmetric(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i64 hKeyHandle,                  // 会话密钥导入后密钥句柄
      3: i32 uiAlgID,                     // 算法标识 (GCM/CCM)
      4: binary pucIV,                    // 缓冲区指针，用于存放输入的 IV 数据
      5: binary pucAAD,                   // 认证数据
      6: binary pucTag,                   // 校验值
      7: binary pucEncData                // 密文数据
    ) throws (1: SvcException ex)

  /*
   * 密钥派生接口
   */
  binary kdf(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i32 uiAlgID,                     // 算法标识
      3: i64 hKeyHandle,                  // 导入会话密钥后获取的密钥句柄
      4: binary pucFixedInputData,        // 固定数据
      5: i32 uiOutputKeyLen               // 希望得到的派生密钥比特长度
    ) throws (1: SvcException ex)

  /*
   * 导出非对称会话密钥公钥明文
   */
  binary exportSessionKeypairPublicKey(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i64 keyHandle                    // 导入会话密钥后返回的句柄
    ) throws (1: SvcException ex)

  /*
   * 导入非对称会话密钥
   */
  i64 importCipherKeypairWithKek(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i32 uiKEKAlgID,                  // 算法标识，指定解密公私钥的对称加密算法
      3: i32 uiKEKIndex,                  // 加密机对称密钥索引
      4: binary pucIV,                    // IV 数据（CBC、GCM、CCM 时不能为空）
      5: binary pucAAD,                   // 附加消息 AAD（GCM、CCM 时不能为空）
      6: binary pucTagData,               // 认证标签数据（GCM、CCM 时不能为空值）
      7: i32 uiAsymAlgID,                 // 导入的非对称密钥算法标识
      8: binary pucPublicKey,             // 会话密钥公钥密文
      9: binary pucPrivateKey             // 会话密钥私钥密文
    ) throws (1: SvcException ex)

  /*
   * 导入明文非对称密钥并使用指定索引对称密钥加密保护，使其成为会话密钥
   */
  KeyPairWithKek importPlainKeypairWithKek(
      1: i64 hSessionHandle,              // 加密机sessionId
      2: i32 uiKEKAlgID,                  // 算法标识，指定加密公私钥的对称加密算法
      3: i32 uiKEKIndex,                  // 加密机对称密钥索引
      4: binary pucIV,                    // IV 数据（CBC、GCM、CCM 时不能为空）
      5: binary pucAAD,                   // 附加消息 AAD（GCM、CCM 时不能为空）
      6: i32 uiAsymAlgID,                 // 导入非对称密钥类型
      7: binary pucPublicKey,             // 公钥分量数据明文
      8: binary pucPlainPrivateKey        // 私钥分量数据明文
    ) throws (1: SvcException ex)


  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                      PKCS11接口
  //////////////////////////////////////////////////////////////////////////////////////////////////////

  p11.Info C_GetInfo() throws (1: p11.P11Exception e)

  list<i32> C_GetSlotList(1: bool tokenPresent) throws (1: p11.P11Exception e)

  p11.SlotInfo C_GetSlotInfo(1: i32 slotID) throws (1: p11.P11Exception e)

  p11.TokenInfo C_GetTokenInfo(1: i32 slotID) throws (1: p11.P11Exception e)

  list<p11.MechanismType> C_GetMechanismList(1: i32 slotID) throws (1: p11.P11Exception e)

  p11.MechanismInfo C_GetMechanismInfo(1: i32 slotID, 2: p11.MechanismType type) throws (1: p11.P11Exception e)

  // void C_InitToken(1: i32 slotID, 2: string pin, 3: string lable) throws (1: p11.P11Exception e)

  // void C_InitPIN(1: i32 session, 2: string pin) throws (1: p11.P11Exception e)

  // void C_SetPIN(1: i32 session, 2: string oldPin, 3: string newPin) throws (1: p11.P11Exception e)

  // i32 C_OpenSession(1: i32 slot, 2: i32 flags) throws (1: p11.P11Exception e)

  // void C_CloseSession(1: i32 session) throws (1: p11.P11Exception e)

  // void C_CloseAllSession(1: i32 slotID) throws (1: p11.P11Exception e)

  // p11.SessionInfo C_GetSessionInfo(1: i32 session) throws (1: p11.P11Exception e)

  // void C_Login(1: i32 session, 2: p11.UserType type, 3: string pin) throws (1: p11.P11Exception e)

  // void C_Logout(1: i32 session) throws (1: p11.P11Exception e)

  p11.Object C_CreateObject(1: p11.Attribute attribute) throws (1: p11.P11Exception e)

  void C_DestroyObject(1: p11.Object object) throws (1: p11.P11Exception e)

  list<p11.Object> C_FindObjects(1: p11.Attribute attribute) throws (1: p11.P11Exception e)

  p11.Data C_Encrypt(1: p11.Mechanism mechanism, 2: p11.Object key, 3: p11.Data data) throws (1: p11.P11Exception e)

  p11.Data C_Decrypt(1: p11.Mechanism mechanism, 2: p11.Object key, 3: p11.Data data) throws (1: p11.P11Exception e)

  p11.Data C_Digest(1: p11.Mechanism mechanism, 2: p11.Data data) throws (1: p11.P11Exception e)

  p11.Data C_Sign(1: p11.Mechanism mechanism, 2: p11.Object key, 3: p11.Data data) throws (1: p11.P11Exception e)

  bool C_Verify(1: p11.Mechanism mechanism, 2: p11.Object key, 3: p11.Data data, 4: p11.Data signature) throws (1: p11.P11Exception e)

  p11.Object C_GenerateKey(1: p11.Mechanism mechanism, 2: p11.Attribute attribute) throws (1: p11.P11Exception e)

  p11.KeyPair C_GenerateKeyPair(1: p11.Mechanism mechanism, 2: p11.Attribute publicKeyAttribute, 3: p11.Attribute privateKeyAttribute) throws (1: p11.P11Exception e)

  p11.Data C_WrapKey(1: p11.Mechanism mechanism, 2: p11.Object wrappingKey, 3: p11.Object key) throws (1: p11.P11Exception e)

  p11.Object C_UnwrapKey(1: p11.Mechanism mechanism, 2: p11.Object unwrappingKey, 3: p11.Data wrappedKey 4: p11.Attribute attribute) throws (1: p11.P11Exception e)

  p11.Data C_GenerateRandom(1: i32 randomLen) throws (1: p11.P11Exception e)

  //////////////////////////////////////////////////////////////////////////////////////////////////////
       //                                      zajk接口
       //////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
         * 生成外部非对称密钥
         */
        AsymKeypair generateAsymKeyPairWithInnerKey(Algo algo,i32 keyIndex) throws (1: SvcException ex)
        /*
         * 生成内部非对称密钥
         */
        void generateInnerAsymKeyPair(Algo algo,i32 keyIndex)  throws (1: SvcException ex)
        /*
         * 外部SM2签名
         */
        binary encPriKeySign(Algo algo,binary encPriKey, binary digest, Algo digestAlgo,i32 keyIndex)  throws (1: SvcException ex)
        /*
         * 外部SM2解密
         */
        binary encPriKeyDecrypt(Algo algo, binary encPriKey, binary data,i32 keyIndex) throws (1: SvcException ex)
        /*
         * 产生会话密钥并指定外部公钥加密
         */
        binary generateSessionKeyByPubKey(Algo pubKeyAlgo, binary pubKey, i32 keyLen) throws (1: SvcException ex)
        /*
         * 将公钥加密的对称密钥转为LMK加密
         */
        binary sessionKeyEncPubKeyToInnerKey(binary encSessionKey, Algo priKeyAlgo, binary encPriKey,i32 keyIndex,i32 innerKeyIndex,bool padding)throws (1: SvcException ex)
        /*
         * 生成对称会话密钥
         */
        binary generateSessionKeyWithInnerKey(i32 keyLen,i32 keyIndex,bool padding)throws (1: SvcException ex)
        /*
         * 会话密钥对称加密
         */
        binary encryptSessionKey(Algo algo, binary sessionKey,SymParam param, binary data,i32 keyIndex,bool padding)throws (1: SvcException ex)
        /*
         * 会话密钥对称解密
         */
        binary decryptSessionKey(Algo algo, binary sessionKey, SymParam param, binary encData,i32 keyIndex,bool padding) throws (1: SvcException ex)
        /*
         * 内部密钥对称加密
         */
        binary encryptScatter(i32 keyIndex,binary key, Algo algo, SymParam param, i32 scatterLevel, list<binary> scatterData, Algo scatterAlgo, SymParam scatterParam, binary data)throws (1: SvcException ex)
        /*
         * 内部密钥对称解密
         */
        binary decryptScatter(i32 keyIndex,binary key, Algo algo, SymParam param, i32 scatterLevel, list<binary> scatterData, Algo scatterAlgo, SymParam scatterParam, binary encData)throws (1: SvcException ex)
        /*
         * 密钥分组对称mac
         */
        binary macScatter(i32 keyIndex,binary key, Algo algo, SymParam param, i32 scatterLevel, list<binary> scatterData, Algo scatterAlgo, SymParam scatterParam,binary data, i32 macLen)throws (1: SvcException ex)
        /*
         * hmac
         */
        binary hmacScatter(i32 keyIndex,binary key, Algo algo, i32 scatterLevel, list<binary> scatterData, Algo scatterAlgo, SymParam scatterParam, binary data, i32 macLen)throws (1: SvcException ex)

        /*
         * 使用内部密钥转加密
         */
        binary convertSymmKey(i32 sKeyIndex,string sLabel,i32 tKeyIndex,string tLabel, SymParam param,binary data,bool padding)throws (1: SvcException ex)
        /*
         * 生成用内部密钥加密的非对称密钥
         */
        AsymKeypair asymGenCipherKeyExpWithInnerKey(Algo algo,i32 keyIndex) throws (1: SvcException ex)
        /*
         * 加密私钥签名
         */
        binary signCipherKey(Algo algo,binary privKey,binary digest,HashAlgoParam hashParam,i32 keyIndex) throws (1: SvcException ex)
        /*
         * 加密私钥解密
         */
        binary asymDecCipherKey(Algo algo,binary privKey, binary data,i32 keyIndex) throws (1: SvcException ex)


        string dispatcher(1:Action action,2:string json) throws(1:SvcException ex)

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 无状态接口
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
          /** 导入明文会话密钥
           * @param data: 会话密钥明文。
           * @return 使用LM key加密的密文。
           */
          binary importSKeyStateless(1:binary data) throws (1: SvcException ex)

          /**  导入ECC（公钥）加密的会话密钥
            * @param index 加密机内部非对称加密密钥索引。使用时注意其对应算法。
            * @param data: 会话密钥密文。
            * @return 使用LM key加密的密文。
            */
          binary importSKeyInAStateless(1:i32 index, 2:binary data) throws (1: SvcException ex)

          /**  导入对称密钥KEK加密的会话密钥
             * @param algID 对称加密算法。
             * @param kekIndex 加密机内部对称密钥索引。使用时注意其对应算法。
             * @param data: 会话密钥密文。
             * @return 使用LM key加密的密文。
             */
          binary importSKeyInSStateless(1:i32 algID, 2:i32 kekIndex, 3:binary data) throws (1: SvcException ex)

            /*
             * 导入非对称会话密钥
             */
            binary importCipherKeypairWithKekStateless(
                1: i32 uiKEKAlgID,                  // 算法标识，指定解密公私钥的对称加密算法
                2: i32 uiKEKIndex,                  // 加密机对称密钥索引
                3: binary pucIV,                    // IV 数据（CBC、GCM、CCM 时不能为空）
                4: binary pucAAD,                   // 附加消息 AAD（GCM、CCM 时不能为空）
                5: binary pucTagData,               // 认证标签数据（GCM、CCM 时不能为空值）
                6: i32 uiAsymAlgID,                 // 导入的非对称密钥算法标识
                7: binary pucPublicKey,             // 会话密钥公钥密文
                8: binary pucPrivateKey             // 会话密钥私钥密文
              ) throws (1: SvcException ex)

            /*
             * 导入明文非对称密钥并使用指定索引对称密钥加密保护，使其成为会话密钥
             */
            KeyPairWithKekStateless importPlainKeypairWithKekStateless(
                1: i32 uiKEKAlgID,                  // 算法标识，指定加密公私钥的对称加密算法
                2: i32 uiKEKIndex,                  // 加密机对称密钥索引
                3: binary pucIV,                    // IV 数据（CBC、GCM、CCM 时不能为空）
                4: binary pucAAD,                   // 附加消息 AAD（GCM、CCM 时不能为空）
                5: i32 uiAsymAlgID,                 // 导入非对称密钥类型
                6: binary pucPublicKey,             // 公钥分量数据明文
                7: binary pucPlainPrivateKey        // 私钥分量数据明文
              ) throws (1: SvcException ex)

             /*
                * 生成非对称会话密钥
                */
               KeyPairWithKekStateless generateKeypairWithKekStateless (
                   1: i32 uiKEKAlgID,              // 加密机对称密算法类型
                   2: i32 uiKEKIndex,              // 加密机对称密钥索引
                   3: binary pucIV,                // 初始化向量值（CBC、GCM、CCM 算法时不能为空）
                   4: binary pucAAD,               // ADD值（非GCM和CCM算法可不传）
                   5: i32 uiAsymAlgID,             // 非对称密钥类型
                   6: i32 uiKeyBits,               // 非对称密钥长度
                   7: i32 uiCurveType              // 曲线类型
                 ) throws (1: SvcException ex)
            /**
             * 生成一对受lmk保护的非对称密钥
             */
            KeyPairWithKekStateless generateKeypairWithLmk (i32 algID) throws (1: SvcException ex)

            /**  生成以内部公钥加密的会话密钥
              * @param index 加密机内部对称密钥索引。使用时注意其对应算法。
              * @param keybits 会话密钥位长度。
              * @return 会话密钥，含句柄sKeyHandle、会话密钥密文。
              */
              IntBinaryStateless exportGenSKeyInAStateless(1:i32 index, 2:i32 keybits) throws (1: SvcException ex)

              /**  生成以外部公钥加密的会话密钥
              * @param algID 非对称算法。
              * @param pubKey 外部公钥，注意与算法匹配。
              * @param keybits 会话密钥位长度。
              * @return 会话密钥，含句柄sKeyHandle、会话密钥密文。
              */
              IntBinaryStateless exportGenSKeyOutAStateless(1:i32 algID, 2:binary pubKey, 3:i32 keybits) throws (1: SvcException ex)

              /**  生成以内部KEK加密的会话密钥
              * @param algID 对称算法。
              * @param index 加密机内部对称密钥索引。使用时注意其对应算法。
              * @param keybits 会话密钥位长度。
              * @return 会话密钥，含句柄sKeyHandle、会话密钥密文。
              */
              IntBinaryStateless exportGenSKeyInSStateless(1:i32 algID, 2:i32 kekIndex, 3:i32 keybits) throws (1: SvcException ex)

            /*
             * RSA 非对称会话密钥签名
             */
            binary signRsaSessionKeyStateless (
                1: binary keyHandle,            // 会话密钥导入后密钥句柄
                2: i32 uiHashAlg,               // 摘要算法标识
                3: i32 uiPadMode,               // 补位模式 RSA_PKCS1_PSS_PADDING和RSA_PKCS1_PADDING
                4: binary pucData               // 待签名密文
              ) throws (1: SvcException ex)

             /*
              * RSA 非对称会话密钥签名验证
              */
             bool verifyRsaSessionKeyStateless (
                 1: binary keyHandle,                // 会话密钥导入后密钥句柄
                 2: i32 uiHashAlg,                   // 摘要算法标识
                 3: i32 uiPadMode,                   // 补位模式 RSA_PKCS1_PSS_PADDING和RSA_PKCS1_PADDING
                 4: binary pucData,                  // 待签名密文
                 5: binary pucSignData               // 签名数据
               ) throws (1: SvcException ex)

            /*
               * 非对称会话密钥加密（RSA类型）
               */
              binary encryptRsaSessionKeypairStateless (
                  1: binary keyHandle,                // 会话密钥导入后密钥句柄
                  2: i32 uiPadMode,                   // 补位模式（1:RSA_NO_PADDING/2:RSA_PKCS1_PADDING/3:RSA_PKCS1_OAEP_PADDING)
                  3: binary pucData                   // 数据明文
                ) throws (1: SvcException ex)

            /*
               * 非对称会话密钥解密（RSA类型）
               */
              binary decryptRsaSessionKeypairStateless (
                  1: binary keyHandle,                   // 会话密钥导入后密钥句柄
                  2: i32 uiPadMode,                   // 补位模式（1:RSA_NO_PADDING/2:RSA_PKCS1_PADDING/3:RSA_PKCS1_OAEP_PADDING)
                  3: binary pucEncData                // 数据密文
                ) throws (1: SvcException ex)

            /*
               * Ec类型非对称会话密钥签名接口
               * (针对SM2和Ec曲线两类密钥)
               */
              binary signSessionKeyStateless (
                  1: binary keyHandle,          // 会话密钥导入后密钥句柄
                  2: binary pucData               // 待签名数据
                ) throws (1: SvcException ex)
             /*
                * Ec类型非对称会话密钥签名验证接口
                * (针对SM2和Ec曲线两类密钥)
                */
               bool verifySessionKeyStateless (
                   1: binary keyHandle,               // 会话密钥导入后密钥句柄
                   2: binary pucData,              // 原文数据
                   3: binary pucSignData           // 签名数据
                 ) throws (1: SvcException ex)

          /*
           * 非对称会话密钥加密（Ec类型）
           */
          binary encryptSessionKeypairStateless (
              1: binary keyHandle,                   // 会话密钥导入后密钥句柄
              2: binary pucData                   // 数据原文
            ) throws (1: SvcException ex)

          /*
           * 非对称会话密钥解密（Ec类型）
           */
          binary decryptSessionKeypairStateless (
              1: binary keyHandle,                   // 会话密钥导入后密钥句柄
              2: binary pucEncData                // 数据密文
          ) throws (1: SvcException ex)

        /** 计算MAC
           * @param sKeyHandle：会话密钥句柄
           * @param algo: 算法
           * @param data：数据
           * @param iv: 初始向量
           * @param mode: 使用对称加密模式
           * @return 消息鉴别码。
           */
          binary macByModeStateless (1:binary sKeyHandle, 2:Algo algo, 3:binary data, 4:SymParam param) throws (1: SvcException ex)

          /**
           *@param role       - 0 发起方、 1 接收方
           *@param myId       - 本方ID
           *@param sKeyHandle - 本方非对称会话密钥（为一对LMK保护的密钥密文）
           *@param myTmpKeyHandle - 本方临时密钥对（为一对LMK保护的密钥密文）
           *@param peerId       - 对方ID
           *@param peerPubKey   - 对方公钥
           *@param peerTmpPubKey - 对方临时公钥
           *@param keyBits       - 协商后输出的密钥长度(bit)
           *@return 协商后的会话密钥（LMK保护）
           */
          binary agreementSm2(
            1:i32 role,
            2:binary myId,
            3:binary sKeyHandle,
            4:binary myTmpKeyHandle,
            5:binary peerId,
            6:binary peerPubKey,
            7:binary peerTmpPubKey,
            8:i32 keyBits
          ) throws (1: SvcException ex)

          /** 密钥协商内部接口
            * @param role: 0 发起方/ 1 接受方
            * @param myId: 本方ID
            * @param keyId: 本方内部SM2密钥索引
            * @param myTmpKeyHandle - 本方临时密钥对（为一对LMK保护的密钥密文）
            * @param peerId: 对方ID
            * @param peerPubkey: 对方公钥
            * @param peerTmpPubkey: 对方临时公钥
            * @param keyBits 协商后输出的密钥长度(bit)
            * @param authCode 私钥权限验证
            * @return 协商出的会话密钥。
            */
            binary agreementSm2In(
                1:i32 role,
                2:binary myId,
                3:i32 keyId,
                4:binary myTmpKeyHandle,
                5:binary peerId,
                6:binary peerPubkey,
                7:binary peerTmpPubkey,
                8:i32 keyBits,
                9:binary authCode) throws (1:SvcException ex)

          /**  使用会话密钥加密
            * @param algo 对称算法。
            * @param sKeyHandle 生成会话密钥输出的句柄。
            * @param param 对称加密参数。
            * @param data 待加密数据。
            * @return 密文。
            */
            binary encSKeyStateless(1: Algo algo, 2: binary sKeyHandle, 3: SymParam param, 4: binary data) throws (1: SvcException ex)

            /**  使用会话密钥解密
            * @param algo 对称算法。
            * @param sKeyHandle 生成会话密钥输出的句柄。
            * @param param 对称加密参数。
            * @param data 密文数据。
            * @return 明文。
            */
            binary decSKeyStateless(1: Algo algo, 2: binary sKeyHandle, 3: SymParam param, 4: binary data) throws (1: SvcException ex)

            /** 使用内部私钥解密
            *
            * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
            * @param data 待加密数据。
            * @param authCode 私钥权限验证码
            * @return 密文。
            */
            binary asymDecInStateless(1:i32 keyID, 2:binary data, 3:binary authCode) throws (1: SvcException ex)

            /** 使用内部私钥运算
            * 主要用于内部RSA私钥运算
            * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
            * @param data 待加密数据。
            * @param withEncKey 是否使用加密密钥对运算。是：使用加密密钥对；否：使用签名密钥对
            * @param authCode 私钥权限验证码
            * @return 密文。
            */
            binary asymPrivOpInStateless(1:i32 keyID, 2:binary data, 3: bool withEncKey,4:binary authCode) throws (1: SvcException ex)

            /**  外部公钥加密输出会话密钥 （非对称会话密钥）
            * @param algID 外部传入公钥的非对称算法。
            * @param pubKey 外部传入公钥。
            * @param sKeyHandle 生成会话密钥输出的句柄。
            * @return 会话密钥密文。
            */
            AsymKeypairStateless expAsymSKeyWithEPKStateless(1:i32 algID, 2:binary pubKey, 3:binary sKeyHandle) throws (1: SvcException ex)

            /**  外部公钥加密输出会话密钥 （对称会话密钥）
            * @param algID 外部传入公钥的非对称算法。
            * @param pubKey 外部传入公钥。
            * @param sKeyHandle 生成会话密钥输出的句柄。
            * @return 会话密钥密文。
            */
            binary expSKeyWithEPKStateless(1:i32 algID, 2:binary pubKey, 3:binary sKeyHandle) throws (1: SvcException ex)

            /**
             * 生成SSL工作密钥
             */
            SslKey generateSslKey(
               1:binary preMasterKeyHandle// 预主密钥句柄
               2:binary clientRandom      // 客户端随机数
               3:binary serverRandom      // 服务端随机数
               4:Algo   prfAlgo           // PRF算法标识
               5:i32    clientHashKeyLen  // 客户端杂凑密钥长度
               6:i32    serverHashKeyLen  // 服务端杂凑密钥长度
               7:i32    clientEncKeyLen   // 客户端加密密钥长度
               8:i32    serverEncKeyLen   // 服务端加密密钥长度
               9:i32    clientIvLen       // 客户端IV长度
              10:i32    serverIvLen       // 服务端IV长度
            ) throws (1: SvcException ex)

            /**  SDF转加密：原使用内部公钥加密，转为外部公钥加密输出
            * @param privKeyIndex 内部非对称索引。
            * @param algo 外部公钥算法。
            * @param pubKey 外部公钥。
            * @param data 密文。
            * @return 转加密后的密文。
            */
            binary exchangeEnvelopeStateless(1:i32 index, 2: Algo algo, 3:binary pubKey, 4:binary data, 5:binary authCode) throws (1: SvcException ex)

            /** 使用内部私钥签名
            * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
            * @param digest 待签名数据的摘要值。
            * @param hashParam 计算摘要时使用的参数。
            * @return 签名结果。
            */
            binary signInStateless(1: i32 keyID, 2: binary digest, 3: HashAlgoParam hashParam, 4:binary authCode) throws (1: SvcException ex)

            /*
            * 生成Ed密钥对明文
            */
            EdDsaKeyPair generateKeyPairEdDsaStateless(
              1: i32 uiAlgID,                 // 指定算法标识，仅支持 SGD_EdDSA
              2: i32 uiKeyBits,               // 指定密钥长度，仅支持 256
              3: i32 uiCurveType              // 指定曲线参数类型，仅支持 1
            ) throws (1: SvcException ex)

            /*
            * 生成Ec密钥对明文
            */
            EcDsaKeyPair generateKeyPairEcDsaStateless(
              1: i32 uiAlgID,                 // 指定算法标识，仅支持 SGD_ECDSA
              2: i32 uiKeyBits,               // 指定密钥长度
              3: i32 uiCurveType              // 椭圆曲线参数
            ) throws (1: SvcException ex)

            /*
            * 非对称会话密钥签名（针对Ed25519，实现Ed25519\Ed25519ph\Ed25519ctx多种算法）
            */
            binary signEdSessionKeyStateless (
              1: binary keyHandle,               // 会话密钥导入后密钥句柄
              2: i32 uiFlag,                  // 签名模式区分标志
              3: binary pucContext,           // 缓冲区指针，ED25519ctx 与 ED25519ph特有，最长为 255 字节
              4: binary pucData               // 待签名数据
            ) throws (1: SvcException ex)

            /*
            * 非对称会话密钥签名验证（针对Ed25519，实现Ed25519\Ed25519ph\Ed25519ctx多种算法）
            */
            bool verifyEdSessionKeyStateless (
              1: binary keyHandle,                   // 会话密钥导入后密钥句柄
              2: i32 uiFlag,                      // 签名模式区分标志
              3: binary pucContext,               // 缓冲区指针，ED25519ctx 与 ED25519ph特有，最长为 255 字节
              4: binary pucData,                  // 待签名数据
              5: binary pucSignData               // 签名数据
            ) throws (1: SvcException ex)

            /*
            * 对称会话密钥加密
            */
            EncryptData encryptSymmetricStateless(
              1: binary hKeyHandle,                  // 会话密钥导入后密钥句柄
              2: i32 uiAlgID,                     // 算法标识 (GCM/CCM)
              3: binary pucIV,                    // 缓冲区指针，用于存放输入的 IV 数据
              4: binary pucAAD,                   // 认证数据
              5: binary pucData                   // 待加密数据
            ) throws (1: SvcException ex)

            /*
            * 对称会话密钥解密
            */
            binary decryptSymmetricStateless (
              1: binary hKeyHandle,                  // 会话密钥导入后密钥句柄
              2: i32 uiAlgID,                     // 算法标识 (GCM/CCM)
              3: binary pucIV,                    // 缓冲区指针，用于存放输入的 IV 数据
              4: binary pucAAD,                   // 认证数据
              5: binary pucTag,                   // 校验值
              6: binary pucEncData                // 密文数据
            ) throws (1: SvcException ex)

            /*
             * 导出非对称会话密钥公钥明文
             */
            binary exportSessionKeypairPublicKeyStateless(
                1: binary keyHandle                  // 导入会话密钥后返回的句柄
            ) throws (1: SvcException ex)

            /*
             * 密钥派生接口
             */
            binary kdfStateless (
                1: i32 uiAlgID,                     // 算法标识
                2: binary hKeyHandle,               // 导入会话密钥后获取的密钥句柄
                3: binary pucFixedInputData,        // 固定数据
                4: i32 uiOutputKeyLen               // 希望得到的派生密钥比特长度
            ) throws (1: SvcException ex)

            /**
            * 使用Lmk转加密由非对称会话密钥保护的密钥
            * @param asymKeyHandle 非对称会话密钥句柄
            * @param algoId        非对称会话密钥算法标识
            * @param cipherKey     密钥密文
            * @return 受lmk保护的密钥密文
            */
            binary importKeyWithAsymKeyHandle(
                1:binary asymKeyHandle,
                2:i32 algoId,
                3:binary cipherKey
            ) throws (1: SvcException ex)

            /**
            * 使用Lmk转加密非对称会话密钥
            */
            binary exportAsmyKeyHandleWithLmk(
                1:i64 sessionId,
                2:i64 keyHandle
            ) throws (1: SvcException ex)

            /**
            * 使用Lmk转加密对称会话密钥
            */
            binary exportKeyHandleWithLmk(
                1:i64 sessionId,
                2:i64 keyHandle
            ) throws (1: SvcException ex)
           /** 外部公钥运算
               * @param pubKey 外部公钥明文
               * @param data 待运算数据。
               * @return 公钥运算结果。
               */
           binary asymPubOp(1:binary pubKey, 2:binary data) throws (1: SvcException ex)
    /** 外部私钥运算
       * 主要用于外部RSA私钥运算
       * @param prikey 私钥
       * @param data 待运算数据。
       * @return 私钥运算结果。
       */
      binary asymPrivOp(1:binary priKey, 2:binary data) throws (1: SvcException ex)
      /**  外部公钥加密输出会话密钥，仅debug模式使用
      * @param sessionId OpenSession返回的Session ID。
      * @param algID 非对称算法。
      * @param pubKey 外部传入公钥。
      * @param sKeyHandle 生成会话密钥输出的句柄。
      * @return 会话密钥密文。
      */
      binary expSKeyWithEPK(1:i64 sessionId, 2:i32 algID, 3:binary pubKey, 4:i64 sKeyHandle) throws (1: SvcException ex)

       /**
       * 数字信封加密
       * @param cert 证书
       * @param data 待加密数据
       * @return 加密数据
         */
       binary envelopeEncryption(1:string cert, 2:binary data) throws (1: SvcException ex)

        /**
           * 数字信封解密
           * @param cert 证书
           * @param privateKey 私钥
           * @param data 待解密数据
           * @return 解密数据
        */
       binary envelopeDecryption(1:string cert, 2:string privateKey,3:binary encData) throws (1: SvcException ex)



	   //////////////////////////////////////////////////////////////////////////////////////////////////////
       //                                      密钥管控接口
       //////////////////////////////////////////////////////////////////////////////////////////////////////

      /**
       * 获取密钥可使用范围
       *
       * @param sessionId             会话ID
       * @return
       * @throws SvcException
       */
    AsymmetricKeyBasic asymmetricGetKeyBasic(1:binary authData,2:Algo algo)throws (1: SvcException ex)


      /**
       * 生成非对称密钥
       *
       * @param sessionId             会话ID
       * @param keyType               密钥类型
       * @param keyIndex              密钥索引
       * @return
       * @throws SvcException
       */
    void asymmetricGenKeyPair(1:binary authData,2:i32 keyType,3:i32 keyIndex,4:Algo algo)throws (1: SvcException ex)

      /**
       * 销毁非对称密钥
       *
       * @param sessionId             会话ID
       * @param keyType               密钥类型
       * @param keyIndex              密钥索引
       * @return
       * @throws SvcException
       */
    void asymmetricDestroyKeyPair(1:binary authData,2:i32 keyType,3:i32 keyIndex)throws (1: SvcException ex)

      /**
       * 获取密钥状态
       *
       * @param sessionId             会话ID
       * @param keyType               密钥类型
       * @param keyIndex              密钥索引
       * @return
       * @throws SvcException
       */
    i32 asymmetricGetStatus(1:binary authData,2:i32 keyType,3:i32 keyIndex)throws (1: SvcException ex)

          /**
           * 获取密钥可使用范围
           *
           * @param sessionId             会话ID
           * @param keyType               密钥类型
           * @return
           * @throws SvcException
           */
    SymmetricKeyBasic symmetricGetKeyBasic(1:binary authData,2:i32 keyType,3:Algo algo)throws (1: SvcException ex)

      /**
       * 生成对称密钥
       *
       * @param sessionId             会话ID
       * @param keyType               密钥类型
       * @param keyIndex              密钥索引
       * @return
       * @throws SvcException
       */
    void symmetricGenSymmetricKey(1:binary authData,2:i32 keyType,3:i32 keyIndex,4:Algo algo)throws (1: SvcException ex)

      /**
       * 销毁对称密钥
       *
       * @param sessionId             会话ID
       * @param keyType               密钥类型
       * @param keyIndex              密钥索引
       * @return
       * @throws SvcException
       */
    void symmetricDestroySymmetricKey(1:binary authData,2:i32 keyType,3:i32 keyIndex)throws (1: SvcException ex)

      /**
       * 获取密钥状态
       *
       * @param sessionId             会话ID
       * @param keyType               密钥类型
       * @param keyIndex              密钥索引
       * @return
       * @throws SvcException
       */
    i32 symmetricGetStatus(1:binary authData,2:i32 keyType,3:i32 keyIndex)throws (1: SvcException ex)

        //////////////////////////////////////////////////////////////////////////////////////////////////////
          //                                      SM9新增接口
          //////////////////////////////////////////////////////////////////////////////////////////////////////

          /**
           * SM9 生成签名主公钥对
           * @param bits         仅支持256bits
           * @return             SM9签名主密钥对
           * @throws SvcException
           */
          SM9SignMasterKeyPair sm9GenerateSignMasterKeyPair(1:i32 bits) throws (1: SvcException ex)

          /**
           * SM9 生成加密主公钥对
           * @param bits         仅支持256bits
           * @return             SM9加密主密钥对
           * @throws SvcException
           */
          SM9EncMasterKeyPair sm9GenerateEncMasterKeyPair(1:i32 bits) throws (1: SvcException ex)

          /** SM9 导出签名主公钥
           *  @param masterIndex 密码机中SM9主密钥索引号
           *  @return            返回SM9签名主公钥(xa,xb,ya,yb)128字节
           */
          binary sm9ExportSignMasterPublicKey(1:i32 masterIndex) throws (1: SvcException ex)

          /** SM9 导出加密主公钥
           *  @param masterIndex 密码机中SM9主密钥索引号
           *  @return            返回SM9加密主公钥(x,y)64字节
           */
          binary sm9ExportEncMasterPublicKey(1:i32 masterIndex) throws (1: SvcException ex)

          /** SM9 生成用户签名私钥
           * @param masterIndex      密码机中SM9主密钥索引号
           * @param auth             私钥访问验证信息
           * @param masterPrivatekey 签名主私钥, 当masterIndex为0时有效
           * @param hid              用户私钥识别符
           * @param userID           用户ID
           * @return                 返回SM9用户签名私钥(x,y)64字节
           */
          binary sm9GenerateSignUserPrivateKey(1:i32 masterIndex, 2:binary auth, 3:binary masterPrivateKey, 4:i8 hid, 5:binary userID) throws (1: SvcException ex)

          /** SM9 生成用户加密私钥
           * @param masterIndex      密码机中SM9主密钥索引号
           * @param auth             私钥访问验证信息
           * @param masterPrivatekey 加密主私钥, 当masterIndex为0时有效
           * @param hid              用户私钥识别符
           * @param userID           用户ID
           * @return                 返回SM9用户加密私钥(xa,xb,ya,yb)128字节
           */
          binary sm9GenerateEncUserPrivateKey(1:i32 masterIndex, 2:binary auth, 3:binary masterPrivateKey, 4:i8 hid, 5:binary userID) throws (1: SvcException ex)

          /**
           * sm9 加密
           *
           * @param data            加密数据
           * @param hid             用户私钥识别符
           * @param id              用户 ID，相当于用户公钥
           * @param masterIndex     加密主公钥索引
           * @param masterPublicKey 加密主公钥，当masterIndex为0时有效
           * @param pairG           加速参数，可以为空，当masterIndex为0时有效
           * @param algo            加密算法0:XOR 1:SM4-ECB 2:SM4-CBC 4:SM4-OFB 8:SM4-CFB
           * @param iv              加密算法为CBC/OFB/CFB时长度为16字节, XOR/ECB模式长度为0
           * @return                密文, (C1,C3,C2), 长度为数据长度+96字节
           * @throws SvcException
           */
          binary sm9Encrypt2(1:binary data, 2:i8 hid, 3:binary id, 4:i32 masterIndex, 5:binary masterPublicKey, 6:binary pairG, 7:i32 algo, 8:binary iv) throws (1: SvcException ex)

          /**
           * sm9 解密
           *
           * @param data       密文, (C1,C3,C2), 长度>96字节
           * @param id         用户ID，相当于用户公钥
           * @param userIndex  密码机内部用户加密私钥索引
           * @param privatekey 私钥明文，index为0时有效
           * @param algo       加密算法0:XOR 1:SM4-ECB 2:SM4-CBC 4:SM4-OFB 8:SM4-CFB
           * @param iv         加密算法为CBC/OFB/CFB时长度为16字节, XOR/ECB模式长度为0
           * @return           原文
           * @throws SvcException
           */
          binary sm9Decrypt2(1:binary data, 2:binary id, 3:i32 userIndex, 4:binary privatekey, 5:i32 algo, 6:binary iv) throws (1: SvcException ex)

          /**
           * sm9 签名
           *
           * @param data            签名数据
           * @param userIndex       密码机内部用户签名私钥索引
           * @param privatekey      私钥明文，index为0时有效
           * @param masterIndex     签名主公钥索引
           * @param masterPublicKey 签名主公钥，当masterIndex为0时有效
           * @param pairG           加速参数，可以为空，当masterIndex为0时有效
           * @return                签名值(h,r,s)长度96字节
           * @throws SvcException
           */
          binary sm9Sign2(1:binary data, 2:i32 userIndex, 3:binary privatekey, 4:i32 masterIndex, 5:binary masterPublicKey, 6:binary pairG) throws (1: SvcException ex)

          /**
           * sm9 验签
           *
           * @param data            签名数据
           * @param hid             用户私钥识别符
           * @param id              用户ID，相当于用户公钥
           * @param signature       签名值(h,r,s)长度96字节
           * @param masterIndex     签名主公钥索引
           * @param masterPublicKey 签名主公钥，当masterIndex为0时有效
           * @param pairG           加速参数，可以为空，当masterIndex为0时有效
           * @return                验证成功true 失败false
           * @throws SvcException
           */
          bool sm9Verify2(1:binary data, 2:i8 hid, 3:binary id, 4:binary signature, 5:i32 masterIndex, 6:binary masterPublicKey, 7:binary pairG) throws (1: SvcException ex)

          /**
           * SM9 密钥封装
           *
           * @param hid              用户私钥识别符
           * @param id               用户ID，相当于用户公钥
           * @param masterIndex      加密主公钥索引
           * @param masterPublicKey  加密主公钥，当masterIndex为0时有效
           * @param pairG            加速参数，可以为空，当masterIndex为0时有效
           * @param keyLen           封装密钥长度
           * @return                 密钥明文、密钥封装(x,y)64字节
           * @throws SvcException
           */
          SM9Encapsulate sm9Encap2(1:i8 hid, 2:binary id, 3:i32 masterIndex, 4:binary masterPublicKey, 5:binary pairG, 6:i32 keyLen) throws (1: SvcException ex)

          /**
           * SM9 密钥解封装
           *
           * @param id              用户 ID，相当于用户公钥
           * @param userIndex       密码机内部用户加密私钥索引
           * @param privatekey      私钥明文，index为0时有效
           * @param keyPack         密钥封装(x,y)64字节
           * @param keyLen          封装密钥长度
           * @return                密钥明文
           * @throws SvcException
           */
          binary sm9Decap2(1:binary id, 2:i32 userIndex, 3:binary privatekey, 4:binary keyPack, 5:i32 keyLen) throws (1: SvcException ex)


          /**
           * SM9 生成密码机内部主密钥索引
           *
           * @param auth            验证信息
           * @param masterIndex     指定的主密钥索引, 当输入的SM9主密钥索引值为0xFFFFFFFF时，输出的主密钥索引值由密码设备内部产生。
           * @param alg             算法（保留）
           * @param arg             参数(保留)
           * @return                实际的主密钥索引
           * @throws SvcException
           */
          i32 sm9GenerateMasterKey(1:binary auth, 2:i32 masterIndex, 3:i32 alg, 4:binary arg) throws (1: SvcException ex)

          /**
           * SM9 销毁密码机内部主密钥索引对应密钥
           *
           * @param auth            验证信息
           * @param masterIndex     指定的主密钥索引
           * @param alg             算法（保留）
           * @param arg             参数(保留)
           * @return
           * @throws SvcException
           */
          bool sm9DestoryMasterKey(1:binary auth, 2:i32 masterIndex, 3:i32 alg, 4:binary arg) throws (1: SvcException ex)

          /**
           * SM9 导出内部主密钥索引对应的密钥
           *
           * @param auth            验证信息
           * @param masterIndex     指定的主密钥索引
           * @param alg             算法（保留）
           * @param arg             参数(保留)
           * @return                主签名密钥对与主加密密钥对
           * @throws SvcException
           */
          SM9MasterKey sm9ExportMasterKey(1:binary auth, 2:i32 masterIndex, 3:i32 alg, 4:binary arg) throws (1: SvcException ex)

          /**
           * SM9 从外部导入主密钥到指定的索引号
           *
           * @param auth            验证信息
           * @param masterIndex     指定的主密钥索引, 当输入的SM9主密钥索引值为0xFFFFFFFF时，输出的主密钥索引值由密码设备内部产生。
           * @param masterKey       主密钥结构体，包含签名主密钥对与加密主密钥对
           * @param alg             算法（保留）
           * @param arg             参数(保留)
           * @return                实际的主密钥索引
           * @throws SvcException
           */
          i32 sm9ImportMasterKey(1:binary auth, 2:i32 masterIndex, 3:SM9MasterKey masterKey, 4:i32 alg, 5:binary arg) throws (1: SvcException ex)


//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                      基于Label的基础运算接口
//////////////////////////////////////////////////////////////////////////////////////////////////////

  /**
   * 获取私钥使用权限
   *
   * @param sessionId OpenSession返回的Session ID。
   * @param keyIndex 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @param password 加密机内部非对称密钥对应的密码，只有密码正确才能获取操作权限。
   * @return 无。
   */
  void getPrivateKeyAccessRightByLabel(1: i64 sessionId, 2: string label, 3: binary password ) throws (1: SvcException ex)

  /**
   * 释放私钥使用权限
   *
   * @param sessionId OpenSession返回的Session ID。
   * @param keyIndex 加密机内部非对称密钥索引。
   * @return 无。
   */
  void releasePrivateKeyAccessRightByLabel(1: i64 sessionId, 2: string label ) throws (1: SvcException ex)

   /** 内部密钥对称加密
   *
   * @param keyID 加密机内部对称密钥索引。使用时注意其对应算法。
   * @param param 对称加密参数。
   * @param data 待加密数据。
   * @return 密文。
   */
  binary encInLabel(1: string label, 2: SymParam param, 3: binary data) throws (1: SvcException ex)

  /** 内部密钥对称解密
     *
     * @param keyID 加密机内部对称密钥索引。使用时注意其对应算法。
     * @param param 对称加密参数。
     * @param data 密文。
     * @return 明文。
     */
   binary decInLabel(1: string label, 2: SymParam param, 3: binary data) throws (1: SvcException ex)

  ///////////////////////////////////////////////////
  // 非对称运算
  ///////////////////////////////////////////////////

  /** 导出内部加密公钥
   *
   * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @return 内部加密公钥。
   */
  binary asymKeyExpEncPubByLabel(1: string label) throws (1: SvcException ex)

  /** 导出内部签名公钥
   *
   * @param keyID 加密机内部非对称密钥索引。使用时注意其对应算法。
   * @return 内部签名公钥。
   */
  binary asymKeyExpSignPubByLabel(1: string label) throws (1: SvcException ex)


  /** 使用内部私钥签名
   *
   * @param identifier index或label的值。
   * @param keyIdentifier 选择index或label。
   * @param isDigest 是否做摘要。
   * @param digestAlgo 摘要算法。
   * @param padding padding。
   * @param data 待签名数据。
   * @param mgfName mgf算法名称。
   * @param saltLen 盐值长度。
   * @return 签名结果。
   */
  binary signByIdentifier(1: binary identifier,2:KeyIdentifier keyIdentifier,3:i32 isDigest,4:string digestAlgo, 5: i32 padding, 6: binary data,7: string mgfName,8:i32 saltLen) throws (1: SvcException ex)


  /** 使用内部公钥验签
   *
   * @param identifier index或label的值。
   * @param keyIdentifier 选择index或label。
   * @param isDigest 是否做摘要。
   * @param digestAlgo 摘要算法。
   * @param padding padding。
   * @param data 待签名数据。
   * @param signData 签名值。
   * @param mgfName mgf算法名称。
   * @param saltLen 盐值长度。
   * @return 签名结果。
   */
  bool verifyByIdentifier( 1: binary identifier,2:KeyIdentifier keyIdentifier,3:i32 isDigest,4:string digestAlgo, 5: i32 padding, 6: binary data,7: binary signData,8: string mgfName,9:i32 saltLen) throws (1: SvcException ex)




  /** 使用外部私钥签名
   *
   * @param privateKey 外部私钥。
   * @param isDigest 是否做摘要。
   * @param digestAlgo 摘要算法。
   * @param padding padding。
   * @param data 待签名数据。
   * @param mgfName mgf算法名称。
   * @param saltLen 盐值长度。
   * @return 签名结果。
   */
  binary rsaSign(1: binary privateKey,2:i32 isDigest,3:string digestAlgo, 4: i32 padding, 5: binary data,6:string mgFname,7:i32 saltLen) throws (1: SvcException ex)


  /** 使用外部公钥验签
   *
   * @param publicKey 外部公钥。
   * @param isDigest 是否做摘要。
   * @param digestAlgo 摘要算法。
   * @param padding padding。
   * @param data 待签名数据。
   * @param signData 签名值。
   * @param mgfName mgf算法名称。
   * @param saltLen 盐值长度。
   * @return 签名结果。
   */
  bool rsaVerify( 1: binary publicKey,2:i32 isDigest,3:string digestAlgo, 4: i32 padding, 5: binary data,6: binary signData,7:string mgFname,8:i32 saltLen) throws (1: SvcException ex)


  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                     非对称加解密
  //////////////////////////////////////////////////////////////////////////////////////////////////////
  /** 使用内部私钥解密
   *
   * @param identifier index或label的值。
   * @param keyIdentifier 选择index或label。
   * @param data 待解密数据。
   * @param padding padding。
   * @return 明文。
   */
  binary asymmetricDecByIdentifier(1: binary identifier,2:KeyIdentifier keyIdentifier, 3:binary data,4:RsaPadding padding) throws (1: SvcException ex)


    /** 使用内部公钥加密
     *
   * @param identifier index或label的值。
   * @param keyIdentifier index或label。
     * @param data 待加密数据。
     * @param padding padding。
     * @return 密文。
     */
    binary asymmetricEncByIdentifier(1: binary identifier,2:KeyIdentifier keyIdentifier, 3: binary data,4:RsaPadding padding) throws (1: SvcException ex)


 /** 使用外部私钥解密(rsa)
      *
      * @param privateKey 私钥
      * @param data 待解密数据。
      * @param padding padding。
      * @return 明文。
      */
     binary rsaDec(1:binary privateKey, 2:binary data,3:RsaPadding padding) throws (1: SvcException ex)

         /** 使用外部公钥加密(rsa)
          *
          * @param publicKey 公钥
          * @param data 待加密数据。
          * @param padding padding。
          * @return 密文。
          */
    binary rsaEnc(1:binary publicKey, 2:binary data,3:RsaPadding padding) throws (1: SvcException ex)



  /** 使用内部索引密钥计算MAC
   * @param keyID: 密钥索引
   * @param algo: 算法
   * @param data: 数据
   * @param iv: 初始向量
   * @param mode: 使用对称加密模式
   * @return 消息鉴别码。
   */
  binary macByModeByLabel(1:string label, 2:Algo algo, 3:binary data, 4:SymParam param) throws (1:SvcException ex)

   //////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                      SM9接口
    //////////////////////////////////////////////////////////////////////////////////////////////////////

    /** SM9算法，导出主公钥
     *  @param uiSM9Index:S在密码机中SM9索引号
     *  @param type:用户功能类型:1-加解密,2-加签验签
     *  @return 返回SM9主公钥
     */
    binary sm9ExportMasterPublicKeyByLabel(1:string uiSM9Label, 2:i32 type) throws (1: SvcException ex)

    /** SM9算法生成用户私钥
     *  @param sm9Index:密码机中SM9索引号
     *  @param userID:用户ID
     *  @param type:用户功能类型:1-加解密,2-加签验签,3-秘钥协商
     *  @return 返回SM9主公钥
     */
    binary sm9GenerateUserPrivateKeyByLabel(1:string sm9Label, 2:binary userID, 3:i32 type) throws (1: SvcException ex)
}

