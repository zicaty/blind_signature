/**
 * Autogenerated by Thrift Compiler (0.21.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package kl.hsm.server.svc.base;

@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked", "unused"})
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.21.0)", date = "2025-01-24")
public class SymmetricKeyBasic implements org.apache.thrift.TBase<SymmetricKeyBasic, SymmetricKeyBasic._Fields>, java.io.Serializable, Cloneable, Comparable<SymmetricKeyBasic> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("SymmetricKeyBasic");

  private static final org.apache.thrift.protocol.TField START_INDEX_FIELD_DESC = new org.apache.thrift.protocol.TField("startIndex", org.apache.thrift.protocol.TType.I32, (short)1);
  private static final org.apache.thrift.protocol.TField END_INDEX_FIELD_DESC = new org.apache.thrift.protocol.TField("endIndex", org.apache.thrift.protocol.TType.I32, (short)2);
  private static final org.apache.thrift.protocol.TField RESERVE_POS_FIELD_DESC = new org.apache.thrift.protocol.TField("reservePos", org.apache.thrift.protocol.TType.I32, (short)3);

  private static final org.apache.thrift.scheme.SchemeFactory STANDARD_SCHEME_FACTORY = new SymmetricKeyBasicStandardSchemeFactory();
  private static final org.apache.thrift.scheme.SchemeFactory TUPLE_SCHEME_FACTORY = new SymmetricKeyBasicTupleSchemeFactory();

  public int startIndex; // required
  public int endIndex; // required
  public int reservePos; // required

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    START_INDEX((short)1, "startIndex"),
    END_INDEX((short)2, "endIndex"),
    RESERVE_POS((short)3, "reservePos");

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
        case 1: // START_INDEX
          return START_INDEX;
        case 2: // END_INDEX
          return END_INDEX;
        case 3: // RESERVE_POS
          return RESERVE_POS;
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
  private static final int __STARTINDEX_ISSET_ID = 0;
  private static final int __ENDINDEX_ISSET_ID = 1;
  private static final int __RESERVEPOS_ISSET_ID = 2;
  private byte __isset_bitfield = 0;
  public static final java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new java.util.EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.START_INDEX, new org.apache.thrift.meta_data.FieldMetaData("startIndex", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I32)));
    tmpMap.put(_Fields.END_INDEX, new org.apache.thrift.meta_data.FieldMetaData("endIndex", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I32)));
    tmpMap.put(_Fields.RESERVE_POS, new org.apache.thrift.meta_data.FieldMetaData("reservePos", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I32)));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(SymmetricKeyBasic.class, metaDataMap);
  }

  public SymmetricKeyBasic() {
  }

  public SymmetricKeyBasic(
    int startIndex,
    int endIndex,
    int reservePos)
  {
    this();
    this.startIndex = startIndex;
    setStartIndexIsSet(true);
    this.endIndex = endIndex;
    setEndIndexIsSet(true);
    this.reservePos = reservePos;
    setReservePosIsSet(true);
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public SymmetricKeyBasic(SymmetricKeyBasic other) {
    __isset_bitfield = other.__isset_bitfield;
    this.startIndex = other.startIndex;
    this.endIndex = other.endIndex;
    this.reservePos = other.reservePos;
  }

  @Override
  public SymmetricKeyBasic deepCopy() {
    return new SymmetricKeyBasic(this);
  }

  @Override
  public void clear() {
    setStartIndexIsSet(false);
    this.startIndex = 0;
    setEndIndexIsSet(false);
    this.endIndex = 0;
    setReservePosIsSet(false);
    this.reservePos = 0;
  }

  public int getStartIndex() {
    return this.startIndex;
  }

  public SymmetricKeyBasic setStartIndex(int startIndex) {
    this.startIndex = startIndex;
    setStartIndexIsSet(true);
    return this;
  }

  public void unsetStartIndex() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __STARTINDEX_ISSET_ID);
  }

  /** Returns true if field startIndex is set (has been assigned a value) and false otherwise */
  public boolean isSetStartIndex() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __STARTINDEX_ISSET_ID);
  }

  public void setStartIndexIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __STARTINDEX_ISSET_ID, value);
  }

  public int getEndIndex() {
    return this.endIndex;
  }

  public SymmetricKeyBasic setEndIndex(int endIndex) {
    this.endIndex = endIndex;
    setEndIndexIsSet(true);
    return this;
  }

  public void unsetEndIndex() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __ENDINDEX_ISSET_ID);
  }

  /** Returns true if field endIndex is set (has been assigned a value) and false otherwise */
  public boolean isSetEndIndex() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __ENDINDEX_ISSET_ID);
  }

  public void setEndIndexIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __ENDINDEX_ISSET_ID, value);
  }

  public int getReservePos() {
    return this.reservePos;
  }

  public SymmetricKeyBasic setReservePos(int reservePos) {
    this.reservePos = reservePos;
    setReservePosIsSet(true);
    return this;
  }

  public void unsetReservePos() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __RESERVEPOS_ISSET_ID);
  }

  /** Returns true if field reservePos is set (has been assigned a value) and false otherwise */
  public boolean isSetReservePos() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __RESERVEPOS_ISSET_ID);
  }

  public void setReservePosIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __RESERVEPOS_ISSET_ID, value);
  }

  @Override
  public void setFieldValue(_Fields field, @org.apache.thrift.annotation.Nullable java.lang.Object value) {
    switch (field) {
    case START_INDEX:
      if (value == null) {
        unsetStartIndex();
      } else {
        setStartIndex((java.lang.Integer)value);
      }
      break;

    case END_INDEX:
      if (value == null) {
        unsetEndIndex();
      } else {
        setEndIndex((java.lang.Integer)value);
      }
      break;

    case RESERVE_POS:
      if (value == null) {
        unsetReservePos();
      } else {
        setReservePos((java.lang.Integer)value);
      }
      break;

    }
  }

  @org.apache.thrift.annotation.Nullable
  @Override
  public java.lang.Object getFieldValue(_Fields field) {
    switch (field) {
    case START_INDEX:
      return getStartIndex();

    case END_INDEX:
      return getEndIndex();

    case RESERVE_POS:
      return getReservePos();

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
    case START_INDEX:
      return isSetStartIndex();
    case END_INDEX:
      return isSetEndIndex();
    case RESERVE_POS:
      return isSetReservePos();
    }
    throw new java.lang.IllegalStateException();
  }

  @Override
  public boolean equals(java.lang.Object that) {
    if (that instanceof SymmetricKeyBasic)
      return this.equals((SymmetricKeyBasic)that);
    return false;
  }

  public boolean equals(SymmetricKeyBasic that) {
    if (that == null)
      return false;
    if (this == that)
      return true;

    boolean this_present_startIndex = true;
    boolean that_present_startIndex = true;
    if (this_present_startIndex || that_present_startIndex) {
      if (!(this_present_startIndex && that_present_startIndex))
        return false;
      if (this.startIndex != that.startIndex)
        return false;
    }

    boolean this_present_endIndex = true;
    boolean that_present_endIndex = true;
    if (this_present_endIndex || that_present_endIndex) {
      if (!(this_present_endIndex && that_present_endIndex))
        return false;
      if (this.endIndex != that.endIndex)
        return false;
    }

    boolean this_present_reservePos = true;
    boolean that_present_reservePos = true;
    if (this_present_reservePos || that_present_reservePos) {
      if (!(this_present_reservePos && that_present_reservePos))
        return false;
      if (this.reservePos != that.reservePos)
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 1;

    hashCode = hashCode * 8191 + startIndex;

    hashCode = hashCode * 8191 + endIndex;

    hashCode = hashCode * 8191 + reservePos;

    return hashCode;
  }

  @Override
  public int compareTo(SymmetricKeyBasic other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = java.lang.Boolean.compare(isSetStartIndex(), other.isSetStartIndex());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetStartIndex()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.startIndex, other.startIndex);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetEndIndex(), other.isSetEndIndex());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetEndIndex()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.endIndex, other.endIndex);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetReservePos(), other.isSetReservePos());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetReservePos()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.reservePos, other.reservePos);
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
    java.lang.StringBuilder sb = new java.lang.StringBuilder("SymmetricKeyBasic(");
    boolean first = true;

    sb.append("startIndex:");
    sb.append(this.startIndex);
    first = false;
    if (!first) sb.append(", ");
    sb.append("endIndex:");
    sb.append(this.endIndex);
    first = false;
    if (!first) sb.append(", ");
    sb.append("reservePos:");
    sb.append(this.reservePos);
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

  private static class SymmetricKeyBasicStandardSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    @Override
    public SymmetricKeyBasicStandardScheme getScheme() {
      return new SymmetricKeyBasicStandardScheme();
    }
  }

  private static class SymmetricKeyBasicStandardScheme extends org.apache.thrift.scheme.StandardScheme<SymmetricKeyBasic> {

    @Override
    public void read(org.apache.thrift.protocol.TProtocol iprot, SymmetricKeyBasic struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // START_INDEX
            if (schemeField.type == org.apache.thrift.protocol.TType.I32) {
              struct.startIndex = iprot.readI32();
              struct.setStartIndexIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // END_INDEX
            if (schemeField.type == org.apache.thrift.protocol.TType.I32) {
              struct.endIndex = iprot.readI32();
              struct.setEndIndexIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 3: // RESERVE_POS
            if (schemeField.type == org.apache.thrift.protocol.TType.I32) {
              struct.reservePos = iprot.readI32();
              struct.setReservePosIsSet(true);
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
    public void write(org.apache.thrift.protocol.TProtocol oprot, SymmetricKeyBasic struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      oprot.writeFieldBegin(START_INDEX_FIELD_DESC);
      oprot.writeI32(struct.startIndex);
      oprot.writeFieldEnd();
      oprot.writeFieldBegin(END_INDEX_FIELD_DESC);
      oprot.writeI32(struct.endIndex);
      oprot.writeFieldEnd();
      oprot.writeFieldBegin(RESERVE_POS_FIELD_DESC);
      oprot.writeI32(struct.reservePos);
      oprot.writeFieldEnd();
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class SymmetricKeyBasicTupleSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    @Override
    public SymmetricKeyBasicTupleScheme getScheme() {
      return new SymmetricKeyBasicTupleScheme();
    }
  }

  private static class SymmetricKeyBasicTupleScheme extends org.apache.thrift.scheme.TupleScheme<SymmetricKeyBasic> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, SymmetricKeyBasic struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol oprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet optionals = new java.util.BitSet();
      if (struct.isSetStartIndex()) {
        optionals.set(0);
      }
      if (struct.isSetEndIndex()) {
        optionals.set(1);
      }
      if (struct.isSetReservePos()) {
        optionals.set(2);
      }
      oprot.writeBitSet(optionals, 3);
      if (struct.isSetStartIndex()) {
        oprot.writeI32(struct.startIndex);
      }
      if (struct.isSetEndIndex()) {
        oprot.writeI32(struct.endIndex);
      }
      if (struct.isSetReservePos()) {
        oprot.writeI32(struct.reservePos);
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, SymmetricKeyBasic struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol iprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet incoming = iprot.readBitSet(3);
      if (incoming.get(0)) {
        struct.startIndex = iprot.readI32();
        struct.setStartIndexIsSet(true);
      }
      if (incoming.get(1)) {
        struct.endIndex = iprot.readI32();
        struct.setEndIndexIsSet(true);
      }
      if (incoming.get(2)) {
        struct.reservePos = iprot.readI32();
        struct.setReservePosIsSet(true);
      }
    }
  }

  private static <S extends org.apache.thrift.scheme.IScheme> S scheme(org.apache.thrift.protocol.TProtocol proto) {
    return (org.apache.thrift.scheme.StandardScheme.class.equals(proto.getScheme()) ? STANDARD_SCHEME_FACTORY : TUPLE_SCHEME_FACTORY).getScheme();
  }
}

