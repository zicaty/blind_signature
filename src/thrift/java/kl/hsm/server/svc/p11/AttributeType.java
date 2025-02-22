/**
 * Autogenerated by Thrift Compiler (0.21.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package kl.hsm.server.svc.p11;


/**
 * 属性类型
 */
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.21.0)", date = "2025-01-24")
public enum AttributeType implements org.apache.thrift.TEnum {
  TCKA_CLASS(0),
  TCKA_TOKEN(1),
  TCKA_PRIVATE(2),
  TCKA_LABEL(3),
  TCKA_APPLICATION(16),
  TCKA_VALUE(17),
  TCKA_OBJECT_ID(18),
  TCKA_CERTIFICATE_TYPE(128),
  TCKA_ISSUER(129),
  TCKA_SERIAL_NUMBER(130),
  TCKA_AC_ISSUER(131),
  TCKA_OWNER(132),
  TCKA_ATTR_TYPES(133),
  TCKA_TRUSTED(134),
  TCKA_CERTIFICATE_CATEGORY(135),
  TCKA_JAVA_MIDP_SECURITY_DOMAIN(136),
  TCKA_URL(137),
  TCKA_HASH_OF_SUBJECT_PUBLIC_KEY(138),
  TCKA_HASH_OF_ISSUER_PUBLIC_KEY(139),
  TCKA_NAME_HASH_ALGORITHM(140),
  TCKA_CHECK_VALUE(144),
  TCKA_KEY_TYPE(256),
  TCKA_SUBJECT(257),
  TCKA_ID(258),
  TCKA_SENSITIVE(259),
  TCKA_ENCRYPT(260),
  TCKA_DECRYPT(261),
  TCKA_WRAP(262),
  TCKA_UNWRAP(263),
  TCKA_SIGN(264),
  TCKA_SIGN_RECOVER(265),
  TCKA_VERIFY(266),
  TCKA_VERIFY_RECOVER(267),
  TCKA_DERIVE(268),
  TCKA_START_DATE(272),
  TCKA_END_DATE(273),
  TCKA_MODULUS(288),
  TCKA_MODULUS_BITS(289),
  TCKA_PUBLIC_EXPONENT(290),
  TCKA_PRIVATE_EXPONENT(291),
  TCKA_PRIME_1(292),
  TCKA_PRIME_2(293),
  TCKA_EXPONENT_1(294),
  TCKA_EXPONENT_2(295),
  TCKA_COEFFICIENT(296),
  TCKA_PUBLIC_KEY_INFO(297),
  TCKA_PRIME(304),
  TCKA_SUBPRIME(305),
  TCKA_BASE(306),
  TCKA_PRIME_BITS(307),
  TCKA_SUBPRIME_BITS(308),
  TCKA_VALUE_BITS(352),
  TCKA_VALUE_LEN(353),
  TCKA_EXTRACTABLE(354),
  TCKA_LOCAL(355),
  TCKA_NEVER_EXTRACTABLE(356),
  TCKA_ALWAYS_SENSITIVE(357),
  TCKA_KEY_GEN_MECHANISM(358),
  TCKA_MODIFIABLE(368),
  TCKA_COPYABLE(369),
  TCKA_DESTROYABLE(370),
  TCKA_EC_PARAMS(384),
  TCKA_EC_POINT(385),
  TCKA_SECONDARY_AUTH(512),
  TCKA_AUTH_PIN_FLAGS(513),
  TCKA_ALWAYS_AUTHENTICATE(514),
  TCKA_WRAP_WITH_TRUSTED(528),
  TCKA_WRAP_TEMPLATE(1073742353),
  TCKA_UNWRAP_TEMPLATE(1073742354),
  TCKA_DERIVE_TEMPLATE(1073742355),
  TCKA_OTP_FORMAT(544),
  TCKA_OTP_LENGTH(545),
  TCKA_OTP_TIME_INTERVAL(546),
  TCKA_OTP_USER_FRIENDLY_MODE(547),
  TCKA_OTP_CHALLENGE_REQUIREMENT(548),
  TCKA_OTP_TIME_REQUIREMENT(549),
  TCKA_OTP_COUNTER_REQUIREMENT(550),
  TCKA_OTP_PIN_REQUIREMENT(551),
  TCKA_OTP_COUNTER(558),
  TCKA_OTP_TIME(559),
  TCKA_OTP_USER_IDENTIFIER(554),
  TCKA_OTP_SERVICE_IDENTIFIER(555),
  TCKA_OTP_SERVICE_LOGO(556),
  TCKA_OTP_SERVICE_LOGO_TYPE(557),
  TCKA_GOSTR3410_PARAMS(592),
  TCKA_GOSTR3411_PARAMS(593),
  TCKA_GOST28147_PARAMS(594),
  TCKA_HW_FEATURE_TYPE(768),
  TCKA_RESET_ON_INIT(769),
  TCKA_HAS_RESET(770),
  TCKA_PIXEL_X(1024),
  TCKA_PIXEL_Y(1025),
  TCKA_RESOLUTION(1026),
  TCKA_CHAR_ROWS(1027),
  TCKA_CHAR_COLUMNS(1028),
  TCKA_COLOR(1029),
  TCKA_BITS_PER_PIXEL(1030),
  TCKA_CHAR_SETS(1152),
  TCKA_ENCODING_METHODS(1153),
  TCKA_MIME_TYPES(1154),
  TCKA_MECHANISM_TYPE(1280),
  TCKA_REQUIRED_CMS_ATTRIBUTES(1281),
  TCKA_DEFAULT_CMS_ATTRIBUTES(1282),
  TCKA_SUPPORTED_CMS_ATTRIBUTES(1283),
  TCKA_ALLOWED_MECHANISMS(1073743360),
  TCKA_VENDOR_DEFINED(-2147483648),
  TCKA_INVALID(-1);

  private final int value;

  private AttributeType(int value) {
    this.value = value;
  }

  /**
   * Get the integer value of this enum value, as defined in the Thrift IDL.
   */
  @Override
  public int getValue() {
    return value;
  }

  /**
   * Find a the enum type by its integer value, as defined in the Thrift IDL.
   * @return null if the value is not found.
   */
  @org.apache.thrift.annotation.Nullable
  public static AttributeType findByValue(int value) { 
    switch (value) {
      case 0:
        return TCKA_CLASS;
      case 1:
        return TCKA_TOKEN;
      case 2:
        return TCKA_PRIVATE;
      case 3:
        return TCKA_LABEL;
      case 16:
        return TCKA_APPLICATION;
      case 17:
        return TCKA_VALUE;
      case 18:
        return TCKA_OBJECT_ID;
      case 128:
        return TCKA_CERTIFICATE_TYPE;
      case 129:
        return TCKA_ISSUER;
      case 130:
        return TCKA_SERIAL_NUMBER;
      case 131:
        return TCKA_AC_ISSUER;
      case 132:
        return TCKA_OWNER;
      case 133:
        return TCKA_ATTR_TYPES;
      case 134:
        return TCKA_TRUSTED;
      case 135:
        return TCKA_CERTIFICATE_CATEGORY;
      case 136:
        return TCKA_JAVA_MIDP_SECURITY_DOMAIN;
      case 137:
        return TCKA_URL;
      case 138:
        return TCKA_HASH_OF_SUBJECT_PUBLIC_KEY;
      case 139:
        return TCKA_HASH_OF_ISSUER_PUBLIC_KEY;
      case 140:
        return TCKA_NAME_HASH_ALGORITHM;
      case 144:
        return TCKA_CHECK_VALUE;
      case 256:
        return TCKA_KEY_TYPE;
      case 257:
        return TCKA_SUBJECT;
      case 258:
        return TCKA_ID;
      case 259:
        return TCKA_SENSITIVE;
      case 260:
        return TCKA_ENCRYPT;
      case 261:
        return TCKA_DECRYPT;
      case 262:
        return TCKA_WRAP;
      case 263:
        return TCKA_UNWRAP;
      case 264:
        return TCKA_SIGN;
      case 265:
        return TCKA_SIGN_RECOVER;
      case 266:
        return TCKA_VERIFY;
      case 267:
        return TCKA_VERIFY_RECOVER;
      case 268:
        return TCKA_DERIVE;
      case 272:
        return TCKA_START_DATE;
      case 273:
        return TCKA_END_DATE;
      case 288:
        return TCKA_MODULUS;
      case 289:
        return TCKA_MODULUS_BITS;
      case 290:
        return TCKA_PUBLIC_EXPONENT;
      case 291:
        return TCKA_PRIVATE_EXPONENT;
      case 292:
        return TCKA_PRIME_1;
      case 293:
        return TCKA_PRIME_2;
      case 294:
        return TCKA_EXPONENT_1;
      case 295:
        return TCKA_EXPONENT_2;
      case 296:
        return TCKA_COEFFICIENT;
      case 297:
        return TCKA_PUBLIC_KEY_INFO;
      case 304:
        return TCKA_PRIME;
      case 305:
        return TCKA_SUBPRIME;
      case 306:
        return TCKA_BASE;
      case 307:
        return TCKA_PRIME_BITS;
      case 308:
        return TCKA_SUBPRIME_BITS;
      case 352:
        return TCKA_VALUE_BITS;
      case 353:
        return TCKA_VALUE_LEN;
      case 354:
        return TCKA_EXTRACTABLE;
      case 355:
        return TCKA_LOCAL;
      case 356:
        return TCKA_NEVER_EXTRACTABLE;
      case 357:
        return TCKA_ALWAYS_SENSITIVE;
      case 358:
        return TCKA_KEY_GEN_MECHANISM;
      case 368:
        return TCKA_MODIFIABLE;
      case 369:
        return TCKA_COPYABLE;
      case 370:
        return TCKA_DESTROYABLE;
      case 384:
        return TCKA_EC_PARAMS;
      case 385:
        return TCKA_EC_POINT;
      case 512:
        return TCKA_SECONDARY_AUTH;
      case 513:
        return TCKA_AUTH_PIN_FLAGS;
      case 514:
        return TCKA_ALWAYS_AUTHENTICATE;
      case 528:
        return TCKA_WRAP_WITH_TRUSTED;
      case 1073742353:
        return TCKA_WRAP_TEMPLATE;
      case 1073742354:
        return TCKA_UNWRAP_TEMPLATE;
      case 1073742355:
        return TCKA_DERIVE_TEMPLATE;
      case 544:
        return TCKA_OTP_FORMAT;
      case 545:
        return TCKA_OTP_LENGTH;
      case 546:
        return TCKA_OTP_TIME_INTERVAL;
      case 547:
        return TCKA_OTP_USER_FRIENDLY_MODE;
      case 548:
        return TCKA_OTP_CHALLENGE_REQUIREMENT;
      case 549:
        return TCKA_OTP_TIME_REQUIREMENT;
      case 550:
        return TCKA_OTP_COUNTER_REQUIREMENT;
      case 551:
        return TCKA_OTP_PIN_REQUIREMENT;
      case 558:
        return TCKA_OTP_COUNTER;
      case 559:
        return TCKA_OTP_TIME;
      case 554:
        return TCKA_OTP_USER_IDENTIFIER;
      case 555:
        return TCKA_OTP_SERVICE_IDENTIFIER;
      case 556:
        return TCKA_OTP_SERVICE_LOGO;
      case 557:
        return TCKA_OTP_SERVICE_LOGO_TYPE;
      case 592:
        return TCKA_GOSTR3410_PARAMS;
      case 593:
        return TCKA_GOSTR3411_PARAMS;
      case 594:
        return TCKA_GOST28147_PARAMS;
      case 768:
        return TCKA_HW_FEATURE_TYPE;
      case 769:
        return TCKA_RESET_ON_INIT;
      case 770:
        return TCKA_HAS_RESET;
      case 1024:
        return TCKA_PIXEL_X;
      case 1025:
        return TCKA_PIXEL_Y;
      case 1026:
        return TCKA_RESOLUTION;
      case 1027:
        return TCKA_CHAR_ROWS;
      case 1028:
        return TCKA_CHAR_COLUMNS;
      case 1029:
        return TCKA_COLOR;
      case 1030:
        return TCKA_BITS_PER_PIXEL;
      case 1152:
        return TCKA_CHAR_SETS;
      case 1153:
        return TCKA_ENCODING_METHODS;
      case 1154:
        return TCKA_MIME_TYPES;
      case 1280:
        return TCKA_MECHANISM_TYPE;
      case 1281:
        return TCKA_REQUIRED_CMS_ATTRIBUTES;
      case 1282:
        return TCKA_DEFAULT_CMS_ATTRIBUTES;
      case 1283:
        return TCKA_SUPPORTED_CMS_ATTRIBUTES;
      case 1073743360:
        return TCKA_ALLOWED_MECHANISMS;
      case -2147483648:
        return TCKA_VENDOR_DEFINED;
      case -1:
        return TCKA_INVALID;
      default:
        return null;
    }
  }
}
