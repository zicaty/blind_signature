/**
 * Autogenerated by Thrift Compiler (0.21.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package kl.hsm.server.svc.p11;

/**
 * RSA-PSS机制参数
 */
@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked", "unused"})
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.21.0)", date = "2025-01-24")
public class PSSParameter implements org.apache.thrift.TBase<PSSParameter, PSSParameter._Fields>, java.io.Serializable, Cloneable, Comparable<PSSParameter> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("PSSParameter");

  private static final org.apache.thrift.protocol.TField HASH_ALG_FIELD_DESC = new org.apache.thrift.protocol.TField("hashAlg", org.apache.thrift.protocol.TType.I32, (short)1);
  private static final org.apache.thrift.protocol.TField MGF_FIELD_DESC = new org.apache.thrift.protocol.TField("mgf", org.apache.thrift.protocol.TType.I32, (short)2);
  private static final org.apache.thrift.protocol.TField S_LEN_FIELD_DESC = new org.apache.thrift.protocol.TField("sLen", org.apache.thrift.protocol.TType.I32, (short)3);

  private static final org.apache.thrift.scheme.SchemeFactory STANDARD_SCHEME_FACTORY = new PSSParameterStandardSchemeFactory();
  private static final org.apache.thrift.scheme.SchemeFactory TUPLE_SCHEME_FACTORY = new PSSParameterTupleSchemeFactory();

  /**
   * 
   * @see MechanismType
   */
  public @org.apache.thrift.annotation.Nullable MechanismType hashAlg; // required
  /**
   * 
   * @see MGF
   */
  public @org.apache.thrift.annotation.Nullable MGF mgf; // required
  public int sLen; // required

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    /**
     * 
     * @see MechanismType
     */
    HASH_ALG((short)1, "hashAlg"),
    /**
     * 
     * @see MGF
     */
    MGF((short)2, "mgf"),
    S_LEN((short)3, "sLen");

    private static final java.util.Map<java.lang.String, _Fields> byName = new java.util.HashMap<java.lang.String, _Fields>();

    static {
      for (_Fields field : java.util.EnumSet.allOf(_Fields.class)) {
        byName.put(field.getFieldName(), field);
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, or null if its not found.
     */
    @org.apache.thrift.annotation.Nullable
    public static _Fields findByThriftId(int fieldId) {
      switch(fieldId) {
        case 1: // HASH_ALG
          return HASH_ALG;
        case 2: // MGF
          return MGF;
        case 3: // S_LEN
          return S_LEN;
        default:
          return null;
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, throwing an exception
     * if it is not found.
     */
    public static _Fields findByThriftIdOrThrow(int fieldId) {
      _Fields fields = findByThriftId(fieldId);
      if (fields == null) throw new java.lang.IllegalArgumentException("Field " + fieldId + " doesn't exist!");
      return fields;
    }

    /**
     * Find the _Fields constant that matches name, or null if its not found.
     */
    @org.apache.thrift.annotation.Nullable
    public static _Fields findByName(java.lang.String name) {
      return byName.get(name);
    }

    private final short _thriftId;
    private final java.lang.String _fieldName;

    _Fields(short thriftId, java.lang.String fieldName) {
      _thriftId = thriftId;
      _fieldName = fieldName;
    }

    @Override
    public short getThriftFieldId() {
      return _thriftId;
    }

    @Override
    public java.lang.String getFieldName() {
      return _fieldName;
    }
  }

  // isset id assignments
  private static final int __SLEN_ISSET_ID = 0;
  private byte __isset_bitfield = 0;
  public static final java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new java.util.EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.HASH_ALG, new org.apache.thrift.meta_data.FieldMetaData("hashAlg", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.EnumMetaData(org.apache.thrift.protocol.TType.ENUM, MechanismType.class)));
    tmpMap.put(_Fields.MGF, new org.apache.thrift.meta_data.FieldMetaData("mgf", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.EnumMetaData(org.apache.thrift.protocol.TType.ENUM, MGF.class)));
    tmpMap.put(_Fields.S_LEN, new org.apache.thrift.meta_data.FieldMetaData("sLen", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I32)));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(PSSParameter.class, metaDataMap);
  }

  public PSSParameter() {
    this.hashAlg = kl.hsm.server.svc.p11.MechanismType.TCKM_INVALID;

    this.mgf = kl.hsm.server.svc.p11.MGF.TCKG_MGF1_INVALID;

    this.sLen = 0;

  }

  public PSSParameter(
    MechanismType hashAlg,
    MGF mgf,
    int sLen)
  {
    this();
    this.hashAlg = hashAlg;
    this.mgf = mgf;
    this.sLen = sLen;
    setSLenIsSet(true);
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public PSSParameter(PSSParameter other) {
    __isset_bitfield = other.__isset_bitfield;
    if (other.isSetHashAlg()) {
      this.hashAlg = other.hashAlg;
    }
    if (other.isSetMgf()) {
      this.mgf = other.mgf;
    }
    this.sLen = other.sLen;
  }

  @Override
  public PSSParameter deepCopy() {
    return new PSSParameter(this);
  }

  @Override
  public void clear() {
    this.hashAlg = kl.hsm.server.svc.p11.MechanismType.TCKM_INVALID;

    this.mgf = kl.hsm.server.svc.p11.MGF.TCKG_MGF1_INVALID;

    this.sLen = 0;

  }

  /**
   * 
   * @see MechanismType
   */
  @org.apache.thrift.annotation.Nullable
  public MechanismType getHashAlg() {
    return this.hashAlg;
  }

  /**
   * 
   * @see MechanismType
   */
  public PSSParameter setHashAlg(@org.apache.thrift.annotation.Nullable MechanismType hashAlg) {
    this.hashAlg = hashAlg;
    return this;
  }

  public void unsetHashAlg() {
    this.hashAlg = null;
  }

  /** Returns true if field hashAlg is set (has been assigned a value) and false otherwise */
  public boolean isSetHashAlg() {
    return this.hashAlg != null;
  }

  public void setHashAlgIsSet(boolean value) {
    if (!value) {
      this.hashAlg = null;
    }
  }

  /**
   * 
   * @see MGF
   */
  @org.apache.thrift.annotation.Nullable
  public MGF getMgf() {
    return this.mgf;
  }

  /**
   * 
   * @see MGF
   */
  public PSSParameter setMgf(@org.apache.thrift.annotation.Nullable MGF mgf) {
    this.mgf = mgf;
    return this;
  }

  public void unsetMgf() {
    this.mgf = null;
  }

  /** Returns true if field mgf is set (has been assigned a value) and false otherwise */
  public boolean isSetMgf() {
    return this.mgf != null;
  }

  public void setMgfIsSet(boolean value) {
    if (!value) {
      this.mgf = null;
    }
  }

  public int getSLen() {
    return this.sLen;
  }

  public PSSParameter setSLen(int sLen) {
    this.sLen = sLen;
    setSLenIsSet(true);
    return this;
  }

  public void unsetSLen() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __SLEN_ISSET_ID);
  }

  /** Returns true if field sLen is set (has been assigned a value) and false otherwise */
  public boolean isSetSLen() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __SLEN_ISSET_ID);
  }

  public void setSLenIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __SLEN_ISSET_ID, value);
  }

  @Override
  public void setFieldValue(_Fields field, @org.apache.thrift.annotation.Nullable java.lang.Object value) {
    switch (field) {
    case HASH_ALG:
      if (value == null) {
        unsetHashAlg();
      } else {
        setHashAlg((MechanismType)value);
      }
      break;

    case MGF:
      if (value == null) {
        unsetMgf();
      } else {
        setMgf((MGF)value);
      }
      break;

    case S_LEN:
      if (value == null) {
        unsetSLen();
      } else {
        setSLen((java.lang.Integer)value);
      }
      break;

    }
  }

  @org.apache.thrift.annotation.Nullable
  @Override
  public java.lang.Object getFieldValue(_Fields field) {
    switch (field) {
    case HASH_ALG:
      return getHashAlg();

    case MGF:
      return getMgf();

    case S_LEN:
      return getSLen();

    }
    throw new java.lang.IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  @Override
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new java.lang.IllegalArgumentException();
    }

    switch (field) {
    case HASH_ALG:
      return isSetHashAlg();
    case MGF:
      return isSetMgf();
    case S_LEN:
      return isSetSLen();
    }
    throw new java.lang.IllegalStateException();
  }

  @Override
  public boolean equals(java.lang.Object that) {
    if (that instanceof PSSParameter)
      return this.equals((PSSParameter)that);
    return false;
  }

  public boolean equals(PSSParameter that) {
    if (that == null)
      return false;
    if (this == that)
      return true;

    boolean this_present_hashAlg = true && this.isSetHashAlg();
    boolean that_present_hashAlg = true && that.isSetHashAlg();
    if (this_present_hashAlg || that_present_hashAlg) {
      if (!(this_present_hashAlg && that_present_hashAlg))
        return false;
      if (!this.hashAlg.equals(that.hashAlg))
        return false;
    }

    boolean this_present_mgf = true && this.isSetMgf();
    boolean that_present_mgf = true && that.isSetMgf();
    if (this_present_mgf || that_present_mgf) {
      if (!(this_present_mgf && that_present_mgf))
        return false;
      if (!this.mgf.equals(that.mgf))
        return false;
    }

    boolean this_present_sLen = true;
    boolean that_present_sLen = true;
    if (this_present_sLen || that_present_sLen) {
      if (!(this_present_sLen && that_present_sLen))
        return false;
      if (this.sLen != that.sLen)
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 1;

    hashCode = hashCode * 8191 + ((isSetHashAlg()) ? 131071 : 524287);
    if (isSetHashAlg())
      hashCode = hashCode * 8191 + hashAlg.getValue();

    hashCode = hashCode * 8191 + ((isSetMgf()) ? 131071 : 524287);
    if (isSetMgf())
      hashCode = hashCode * 8191 + mgf.getValue();

    hashCode = hashCode * 8191 + sLen;

    return hashCode;
  }

  @Override
  public int compareTo(PSSParameter other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = java.lang.Boolean.compare(isSetHashAlg(), other.isSetHashAlg());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetHashAlg()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.hashAlg, other.hashAlg);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetMgf(), other.isSetMgf());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetMgf()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.mgf, other.mgf);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetSLen(), other.isSetSLen());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetSLen()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.sLen, other.sLen);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    return 0;
  }

  @org.apache.thrift.annotation.Nullable
  @Override
  public _Fields fieldForId(int fieldId) {
    return _Fields.findByThriftId(fieldId);
  }

  @Override
  public void read(org.apache.thrift.protocol.TProtocol iprot) throws org.apache.thrift.TException {
    scheme(iprot).read(iprot, this);
  }

  @Override
  public void write(org.apache.thrift.protocol.TProtocol oprot) throws org.apache.thrift.TException {
    scheme(oprot).write(oprot, this);
  }

  @Override
  public java.lang.String toString() {
    java.lang.StringBuilder sb = new java.lang.StringBuilder("PSSParameter(");
    boolean first = true;

    sb.append("hashAlg:");
    if (this.hashAlg == null) {
      sb.append("null");
    } else {
      sb.append(this.hashAlg);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("mgf:");
    if (this.mgf == null) {
      sb.append("null");
    } else {
      sb.append(this.mgf);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("sLen:");
    sb.append(this.sLen);
    first = false;
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    // check for sub-struct validity
  }

  private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
    try {
      write(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(out)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private void readObject(java.io.ObjectInputStream in) throws java.io.IOException, java.lang.ClassNotFoundException {
    try {
      // it doesn't seem like you should have to do this, but java serialization is wacky, and doesn't call the default constructor.
      __isset_bitfield = 0;
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class PSSParameterStandardSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    @Override
    public PSSParameterStandardScheme getScheme() {
      return new PSSParameterStandardScheme();
    }
  }

  private static class PSSParameterStandardScheme extends org.apache.thrift.scheme.StandardScheme<PSSParameter> {

    @Override
    public void read(org.apache.thrift.protocol.TProtocol iprot, PSSParameter struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // HASH_ALG
            if (schemeField.type == org.apache.thrift.protocol.TType.I32) {
              struct.hashAlg = kl.hsm.server.svc.p11.MechanismType.findByValue(iprot.readI32());
              struct.setHashAlgIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // MGF
            if (schemeField.type == org.apache.thrift.protocol.TType.I32) {
              struct.mgf = kl.hsm.server.svc.p11.MGF.findByValue(iprot.readI32());
              struct.setMgfIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 3: // S_LEN
            if (schemeField.type == org.apache.thrift.protocol.TType.I32) {
              struct.sLen = iprot.readI32();
              struct.setSLenIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          default:
            org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
        }
        iprot.readFieldEnd();
      }
      iprot.readStructEnd();

      // check for required fields of primitive type, which can't be checked in the validate method
      struct.validate();
    }

    @Override
    public void write(org.apache.thrift.protocol.TProtocol oprot, PSSParameter struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      if (struct.hashAlg != null) {
        oprot.writeFieldBegin(HASH_ALG_FIELD_DESC);
        oprot.writeI32(struct.hashAlg.getValue());
        oprot.writeFieldEnd();
      }
      if (struct.mgf != null) {
        oprot.writeFieldBegin(MGF_FIELD_DESC);
        oprot.writeI32(struct.mgf.getValue());
        oprot.writeFieldEnd();
      }
      oprot.writeFieldBegin(S_LEN_FIELD_DESC);
      oprot.writeI32(struct.sLen);
      oprot.writeFieldEnd();
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class PSSParameterTupleSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    @Override
    public PSSParameterTupleScheme getScheme() {
      return new PSSParameterTupleScheme();
    }
  }

  private static class PSSParameterTupleScheme extends org.apache.thrift.scheme.TupleScheme<PSSParameter> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, PSSParameter struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol oprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet optionals = new java.util.BitSet();
      if (struct.isSetHashAlg()) {
        optionals.set(0);
      }
      if (struct.isSetMgf()) {
        optionals.set(1);
      }
      if (struct.isSetSLen()) {
        optionals.set(2);
      }
      oprot.writeBitSet(optionals, 3);
      if (struct.isSetHashAlg()) {
        oprot.writeI32(struct.hashAlg.getValue());
      }
      if (struct.isSetMgf()) {
        oprot.writeI32(struct.mgf.getValue());
      }
      if (struct.isSetSLen()) {
        oprot.writeI32(struct.sLen);
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, PSSParameter struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol iprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet incoming = iprot.readBitSet(3);
      if (incoming.get(0)) {
        struct.hashAlg = kl.hsm.server.svc.p11.MechanismType.findByValue(iprot.readI32());
        struct.setHashAlgIsSet(true);
      }
      if (incoming.get(1)) {
        struct.mgf = kl.hsm.server.svc.p11.MGF.findByValue(iprot.readI32());
        struct.setMgfIsSet(true);
      }
      if (incoming.get(2)) {
        struct.sLen = iprot.readI32();
        struct.setSLenIsSet(true);
      }
    }
  }

  private static <S extends org.apache.thrift.scheme.IScheme> S scheme(org.apache.thrift.protocol.TProtocol proto) {
    return (org.apache.thrift.scheme.StandardScheme.class.equals(proto.getScheme()) ? STANDARD_SCHEME_FACTORY : TUPLE_SCHEME_FACTORY).getScheme();
  }
}

