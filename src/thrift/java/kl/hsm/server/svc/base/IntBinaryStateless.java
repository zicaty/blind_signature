/**
 * Autogenerated by Thrift Compiler (0.21.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package kl.hsm.server.svc.base;

@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked", "unused"})
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.21.0)", date = "2025-01-24")
public class IntBinaryStateless implements org.apache.thrift.TBase<IntBinaryStateless, IntBinaryStateless._Fields>, java.io.Serializable, Cloneable, Comparable<IntBinaryStateless> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("IntBinaryStateless");

  private static final org.apache.thrift.protocol.TField HANDLER_FIELD_DESC = new org.apache.thrift.protocol.TField("handler", org.apache.thrift.protocol.TType.STRING, (short)1);
  private static final org.apache.thrift.protocol.TField KEY_FIELD_DESC = new org.apache.thrift.protocol.TField("key", org.apache.thrift.protocol.TType.STRING, (short)2);

  private static final org.apache.thrift.scheme.SchemeFactory STANDARD_SCHEME_FACTORY = new IntBinaryStatelessStandardSchemeFactory();
  private static final org.apache.thrift.scheme.SchemeFactory TUPLE_SCHEME_FACTORY = new IntBinaryStatelessTupleSchemeFactory();

  public @org.apache.thrift.annotation.Nullable java.nio.ByteBuffer handler; // required
  public @org.apache.thrift.annotation.Nullable java.nio.ByteBuffer key; // required

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    HANDLER((short)1, "handler"),
    KEY((short)2, "key");

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
        case 1: // HANDLER
          return HANDLER;
        case 2: // KEY
          return KEY;
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
    tmpMap.put(_Fields.HANDLER, new org.apache.thrift.meta_data.FieldMetaData("handler", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING        , true)));
    tmpMap.put(_Fields.KEY, new org.apache.thrift.meta_data.FieldMetaData("key", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING        , true)));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(IntBinaryStateless.class, metaDataMap);
  }

  public IntBinaryStateless() {
  }

  public IntBinaryStateless(
    java.nio.ByteBuffer handler,
    java.nio.ByteBuffer key)
  {
    this();
    this.handler = org.apache.thrift.TBaseHelper.copyBinary(handler);
    this.key = org.apache.thrift.TBaseHelper.copyBinary(key);
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public IntBinaryStateless(IntBinaryStateless other) {
    if (other.isSetHandler()) {
      this.handler = org.apache.thrift.TBaseHelper.copyBinary(other.handler);
    }
    if (other.isSetKey()) {
      this.key = org.apache.thrift.TBaseHelper.copyBinary(other.key);
    }
  }

  @Override
  public IntBinaryStateless deepCopy() {
    return new IntBinaryStateless(this);
  }

  @Override
  public void clear() {
    this.handler = null;
    this.key = null;
  }

  public byte[] getHandler() {
    setHandler(org.apache.thrift.TBaseHelper.rightSize(handler));
    return handler == null ? null : handler.array();
  }

  public java.nio.ByteBuffer bufferForHandler() {
    return org.apache.thrift.TBaseHelper.copyBinary(handler);
  }

  public IntBinaryStateless setHandler(byte[] handler) {
    this.handler = handler == null ? (java.nio.ByteBuffer)null   : java.nio.ByteBuffer.wrap(handler.clone());
    return this;
  }

  public IntBinaryStateless setHandler(@org.apache.thrift.annotation.Nullable java.nio.ByteBuffer handler) {
    this.handler = org.apache.thrift.TBaseHelper.copyBinary(handler);
    return this;
  }

  public void unsetHandler() {
    this.handler = null;
  }

  /** Returns true if field handler is set (has been assigned a value) and false otherwise */
  public boolean isSetHandler() {
    return this.handler != null;
  }

  public void setHandlerIsSet(boolean value) {
    if (!value) {
      this.handler = null;
    }
  }

  public byte[] getKey() {
    setKey(org.apache.thrift.TBaseHelper.rightSize(key));
    return key == null ? null : key.array();
  }

  public java.nio.ByteBuffer bufferForKey() {
    return org.apache.thrift.TBaseHelper.copyBinary(key);
  }

  public IntBinaryStateless setKey(byte[] key) {
    this.key = key == null ? (java.nio.ByteBuffer)null   : java.nio.ByteBuffer.wrap(key.clone());
    return this;
  }

  public IntBinaryStateless setKey(@org.apache.thrift.annotation.Nullable java.nio.ByteBuffer key) {
    this.key = org.apache.thrift.TBaseHelper.copyBinary(key);
    return this;
  }

  public void unsetKey() {
    this.key = null;
  }

  /** Returns true if field key is set (has been assigned a value) and false otherwise */
  public boolean isSetKey() {
    return this.key != null;
  }

  public void setKeyIsSet(boolean value) {
    if (!value) {
      this.key = null;
    }
  }

  @Override
  public void setFieldValue(_Fields field, @org.apache.thrift.annotation.Nullable java.lang.Object value) {
    switch (field) {
    case HANDLER:
      if (value == null) {
        unsetHandler();
      } else {
        if (value instanceof byte[]) {
          setHandler((byte[])value);
        } else {
          setHandler((java.nio.ByteBuffer)value);
        }
      }
      break;

    case KEY:
      if (value == null) {
        unsetKey();
      } else {
        if (value instanceof byte[]) {
          setKey((byte[])value);
        } else {
          setKey((java.nio.ByteBuffer)value);
        }
      }
      break;

    }
  }

  @org.apache.thrift.annotation.Nullable
  @Override
  public java.lang.Object getFieldValue(_Fields field) {
    switch (field) {
    case HANDLER:
      return getHandler();

    case KEY:
      return getKey();

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
    case HANDLER:
      return isSetHandler();
    case KEY:
      return isSetKey();
    }
    throw new java.lang.IllegalStateException();
  }

  @Override
  public boolean equals(java.lang.Object that) {
    if (that instanceof IntBinaryStateless)
      return this.equals((IntBinaryStateless)that);
    return false;
  }

  public boolean equals(IntBinaryStateless that) {
    if (that == null)
      return false;
    if (this == that)
      return true;

    boolean this_present_handler = true && this.isSetHandler();
    boolean that_present_handler = true && that.isSetHandler();
    if (this_present_handler || that_present_handler) {
      if (!(this_present_handler && that_present_handler))
        return false;
      if (!this.handler.equals(that.handler))
        return false;
    }

    boolean this_present_key = true && this.isSetKey();
    boolean that_present_key = true && that.isSetKey();
    if (this_present_key || that_present_key) {
      if (!(this_present_key && that_present_key))
        return false;
      if (!this.key.equals(that.key))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 1;

    hashCode = hashCode * 8191 + ((isSetHandler()) ? 131071 : 524287);
    if (isSetHandler())
      hashCode = hashCode * 8191 + handler.hashCode();

    hashCode = hashCode * 8191 + ((isSetKey()) ? 131071 : 524287);
    if (isSetKey())
      hashCode = hashCode * 8191 + key.hashCode();

    return hashCode;
  }

  @Override
  public int compareTo(IntBinaryStateless other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = java.lang.Boolean.compare(isSetHandler(), other.isSetHandler());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetHandler()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.handler, other.handler);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetKey(), other.isSetKey());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetKey()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.key, other.key);
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
    java.lang.StringBuilder sb = new java.lang.StringBuilder("IntBinaryStateless(");
    boolean first = true;

    sb.append("handler:");
    if (this.handler == null) {
      sb.append("null");
    } else {
      org.apache.thrift.TBaseHelper.toString(this.handler, sb);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("key:");
    if (this.key == null) {
      sb.append("null");
    } else {
      org.apache.thrift.TBaseHelper.toString(this.key, sb);
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

  private static class IntBinaryStatelessStandardSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    @Override
    public IntBinaryStatelessStandardScheme getScheme() {
      return new IntBinaryStatelessStandardScheme();
    }
  }

  private static class IntBinaryStatelessStandardScheme extends org.apache.thrift.scheme.StandardScheme<IntBinaryStateless> {

    @Override
    public void read(org.apache.thrift.protocol.TProtocol iprot, IntBinaryStateless struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // HANDLER
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.handler = iprot.readBinary();
              struct.setHandlerIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // KEY
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.key = iprot.readBinary();
              struct.setKeyIsSet(true);
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
    public void write(org.apache.thrift.protocol.TProtocol oprot, IntBinaryStateless struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      if (struct.handler != null) {
        oprot.writeFieldBegin(HANDLER_FIELD_DESC);
        oprot.writeBinary(struct.handler);
        oprot.writeFieldEnd();
      }
      if (struct.key != null) {
        oprot.writeFieldBegin(KEY_FIELD_DESC);
        oprot.writeBinary(struct.key);
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class IntBinaryStatelessTupleSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    @Override
    public IntBinaryStatelessTupleScheme getScheme() {
      return new IntBinaryStatelessTupleScheme();
    }
  }

  private static class IntBinaryStatelessTupleScheme extends org.apache.thrift.scheme.TupleScheme<IntBinaryStateless> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, IntBinaryStateless struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol oprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet optionals = new java.util.BitSet();
      if (struct.isSetHandler()) {
        optionals.set(0);
      }
      if (struct.isSetKey()) {
        optionals.set(1);
      }
      oprot.writeBitSet(optionals, 2);
      if (struct.isSetHandler()) {
        oprot.writeBinary(struct.handler);
      }
      if (struct.isSetKey()) {
        oprot.writeBinary(struct.key);
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, IntBinaryStateless struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol iprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet incoming = iprot.readBitSet(2);
      if (incoming.get(0)) {
        struct.handler = iprot.readBinary();
        struct.setHandlerIsSet(true);
      }
      if (incoming.get(1)) {
        struct.key = iprot.readBinary();
        struct.setKeyIsSet(true);
      }
    }
  }

  private static <S extends org.apache.thrift.scheme.IScheme> S scheme(org.apache.thrift.protocol.TProtocol proto) {
    return (org.apache.thrift.scheme.StandardScheme.class.equals(proto.getScheme()) ? STANDARD_SCHEME_FACTORY : TUPLE_SCHEME_FACTORY).getScheme();
  }
}

