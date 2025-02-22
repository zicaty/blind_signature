/**
 * Autogenerated by Thrift Compiler (0.21.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package kl.hsm.server.svc.p11;

/**
 * 默认机制参数
 */
@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked", "unused"})
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.21.0)", date = "2025-01-24")
public class DefaultParameter implements org.apache.thrift.TBase<DefaultParameter, DefaultParameter._Fields>, java.io.Serializable, Cloneable, Comparable<DefaultParameter> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("DefaultParameter");

  private static final org.apache.thrift.protocol.TField PARAMETER_FIELD_DESC = new org.apache.thrift.protocol.TField("parameter", org.apache.thrift.protocol.TType.STRING, (short)1);

  private static final org.apache.thrift.scheme.SchemeFactory STANDARD_SCHEME_FACTORY = new DefaultParameterStandardSchemeFactory();
  private static final org.apache.thrift.scheme.SchemeFactory TUPLE_SCHEME_FACTORY = new DefaultParameterTupleSchemeFactory();

  public @org.apache.thrift.annotation.Nullable java.nio.ByteBuffer parameter; // required

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    PARAMETER((short)1, "parameter");

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
        case 1: // PARAMETER
          return PARAMETER;
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
  public static final java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new java.util.EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.PARAMETER, new org.apache.thrift.meta_data.FieldMetaData("parameter", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING        , true)));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(DefaultParameter.class, metaDataMap);
  }

  public DefaultParameter() {
  }

  public DefaultParameter(
    java.nio.ByteBuffer parameter)
  {
    this();
    this.parameter = org.apache.thrift.TBaseHelper.copyBinary(parameter);
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public DefaultParameter(DefaultParameter other) {
    if (other.isSetParameter()) {
      this.parameter = org.apache.thrift.TBaseHelper.copyBinary(other.parameter);
    }
  }

  @Override
  public DefaultParameter deepCopy() {
    return new DefaultParameter(this);
  }

  @Override
  public void clear() {
    this.parameter = null;
  }

  public byte[] getParameter() {
    setParameter(org.apache.thrift.TBaseHelper.rightSize(parameter));
    return parameter == null ? null : parameter.array();
  }

  public java.nio.ByteBuffer bufferForParameter() {
    return org.apache.thrift.TBaseHelper.copyBinary(parameter);
  }

  public DefaultParameter setParameter(byte[] parameter) {
    this.parameter = parameter == null ? (java.nio.ByteBuffer)null   : java.nio.ByteBuffer.wrap(parameter.clone());
    return this;
  }

  public DefaultParameter setParameter(@org.apache.thrift.annotation.Nullable java.nio.ByteBuffer parameter) {
    this.parameter = org.apache.thrift.TBaseHelper.copyBinary(parameter);
    return this;
  }

  public void unsetParameter() {
    this.parameter = null;
  }

  /** Returns true if field parameter is set (has been assigned a value) and false otherwise */
  public boolean isSetParameter() {
    return this.parameter != null;
  }

  public void setParameterIsSet(boolean value) {
    if (!value) {
      this.parameter = null;
    }
  }

  @Override
  public void setFieldValue(_Fields field, @org.apache.thrift.annotation.Nullable java.lang.Object value) {
    switch (field) {
    case PARAMETER:
      if (value == null) {
        unsetParameter();
      } else {
        if (value instanceof byte[]) {
          setParameter((byte[])value);
        } else {
          setParameter((java.nio.ByteBuffer)value);
        }
      }
      break;

    }
  }

  @org.apache.thrift.annotation.Nullable
  @Override
  public java.lang.Object getFieldValue(_Fields field) {
    switch (field) {
    case PARAMETER:
      return getParameter();

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
    case PARAMETER:
      return isSetParameter();
    }
    throw new java.lang.IllegalStateException();
  }

  @Override
  public boolean equals(java.lang.Object that) {
    if (that instanceof DefaultParameter)
      return this.equals((DefaultParameter)that);
    return false;
  }

  public boolean equals(DefaultParameter that) {
    if (that == null)
      return false;
    if (this == that)
      return true;

    boolean this_present_parameter = true && this.isSetParameter();
    boolean that_present_parameter = true && that.isSetParameter();
    if (this_present_parameter || that_present_parameter) {
      if (!(this_present_parameter && that_present_parameter))
        return false;
      if (!this.parameter.equals(that.parameter))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 1;

    hashCode = hashCode * 8191 + ((isSetParameter()) ? 131071 : 524287);
    if (isSetParameter())
      hashCode = hashCode * 8191 + parameter.hashCode();

    return hashCode;
  }

  @Override
  public int compareTo(DefaultParameter other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = java.lang.Boolean.compare(isSetParameter(), other.isSetParameter());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetParameter()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.parameter, other.parameter);
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
    java.lang.StringBuilder sb = new java.lang.StringBuilder("DefaultParameter(");
    boolean first = true;

    sb.append("parameter:");
    if (this.parameter == null) {
      sb.append("null");
    } else {
      org.apache.thrift.TBaseHelper.toString(this.parameter, sb);
    }
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
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class DefaultParameterStandardSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    @Override
    public DefaultParameterStandardScheme getScheme() {
      return new DefaultParameterStandardScheme();
    }
  }

  private static class DefaultParameterStandardScheme extends org.apache.thrift.scheme.StandardScheme<DefaultParameter> {

    @Override
    public void read(org.apache.thrift.protocol.TProtocol iprot, DefaultParameter struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // PARAMETER
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.parameter = iprot.readBinary();
              struct.setParameterIsSet(true);
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
    public void write(org.apache.thrift.protocol.TProtocol oprot, DefaultParameter struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      if (struct.parameter != null) {
        oprot.writeFieldBegin(PARAMETER_FIELD_DESC);
        oprot.writeBinary(struct.parameter);
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class DefaultParameterTupleSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    @Override
    public DefaultParameterTupleScheme getScheme() {
      return new DefaultParameterTupleScheme();
    }
  }

  private static class DefaultParameterTupleScheme extends org.apache.thrift.scheme.TupleScheme<DefaultParameter> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, DefaultParameter struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol oprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet optionals = new java.util.BitSet();
      if (struct.isSetParameter()) {
        optionals.set(0);
      }
      oprot.writeBitSet(optionals, 1);
      if (struct.isSetParameter()) {
        oprot.writeBinary(struct.parameter);
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, DefaultParameter struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol iprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet incoming = iprot.readBitSet(1);
      if (incoming.get(0)) {
        struct.parameter = iprot.readBinary();
        struct.setParameterIsSet(true);
      }
    }
  }

  private static <S extends org.apache.thrift.scheme.IScheme> S scheme(org.apache.thrift.protocol.TProtocol proto) {
    return (org.apache.thrift.scheme.StandardScheme.class.equals(proto.getScheme()) ? STANDARD_SCHEME_FACTORY : TUPLE_SCHEME_FACTORY).getScheme();
  }
}

