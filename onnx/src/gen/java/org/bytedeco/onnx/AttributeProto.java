// Targeted by JavaCPP version 1.5.12-SNAPSHOT: DO NOT EDIT THIS FILE

package org.bytedeco.onnx;

import java.nio.*;
import org.bytedeco.javacpp.*;
import org.bytedeco.javacpp.annotation.*;

import static org.bytedeco.javacpp.presets.javacpp.*;

import static org.bytedeco.onnx.global.onnx.*;

// ===================================================================

@Namespace("onnx") @NoOffset @Properties(inherit = org.bytedeco.onnx.presets.onnx.class)
public class AttributeProto extends MessageLite {
    static { Loader.load(); }
    /** Pointer cast constructor. Invokes {@link Pointer#Pointer(Pointer)}. */
    public AttributeProto(Pointer p) { super(p); }
    /** Native array allocator. Access with {@link Pointer#position(long)}. */
    public AttributeProto(long size) { super((Pointer)null); allocateArray(size); }
    private native void allocateArray(long size);
    @Override public AttributeProto position(long position) {
        return (AttributeProto)super.position(position);
    }
    @Override public AttributeProto getPointer(long i) {
        return new AttributeProto((Pointer)this).offsetAddress(i);
    }

  public AttributeProto() { super((Pointer)null); allocate(); }
  private native void allocate();

  public AttributeProto(@Const @ByRef AttributeProto from) { super((Pointer)null); allocate(from); }
  private native void allocate(@Const @ByRef AttributeProto from);

  public native @ByRef @Name("operator =") AttributeProto put(@Const @ByRef AttributeProto from);

  public native @StdString BytePointer unknown_fields();
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer mutable_unknown_fields();

  public static native @Const @ByRef AttributeProto default_instance();
  public static native @Const AttributeProto internal_default_instance();
  @MemberGetter public static native int kIndexInFileMessages();
  public static final int kIndexInFileMessages = kIndexInFileMessages();

  
  public native void Swap(AttributeProto other);
  public native void UnsafeArenaSwap(AttributeProto other);

  // implements Message ----------------------------------------------

  public native AttributeProto New(Arena arena/*=nullptr*/);
  public native AttributeProto New();
  public native void CheckTypeAndMergeFrom(@Const @ByRef MessageLite from);
  public native void CopyFrom(@Const @ByRef AttributeProto from);
  public native void MergeFrom(@Const @ByRef AttributeProto from);
  public native void Clear();
  public native @Cast("bool") boolean IsInitialized();

  public native @Cast("size_t") long ByteSizeLong();
  public native @Cast("const char*") BytePointer _InternalParse(@Cast("const char*") BytePointer ptr, ParseContext ctx);
  public native String _InternalParse(String ptr, ParseContext ctx);
  public native int GetCachedSize();

  public native @StdString BytePointer GetTypeName();

  // nested types ----------------------------------------------------
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int UNDEFINED();
  public static final int UNDEFINED = UNDEFINED();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int FLOAT();
  public static final int FLOAT = FLOAT();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int INT();
  public static final int INT = INT();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int STRING();
  public static final int STRING = STRING();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int TENSOR();
  public static final int TENSOR = TENSOR();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int GRAPH();
  public static final int GRAPH = GRAPH();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int SPARSE_TENSOR();
  public static final int SPARSE_TENSOR = SPARSE_TENSOR();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int TYPE_PROTO();
  public static final int TYPE_PROTO = TYPE_PROTO();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int FLOATS();
  public static final int FLOATS = FLOATS();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int INTS();
  public static final int INTS = INTS();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int STRINGS();
  public static final int STRINGS = STRINGS();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int TENSORS();
  public static final int TENSORS = TENSORS();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int GRAPHS();
  public static final int GRAPHS = GRAPHS();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int SPARSE_TENSORS();
  public static final int SPARSE_TENSORS = SPARSE_TENSORS();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int TYPE_PROTOS();
  public static final int TYPE_PROTOS = TYPE_PROTOS();
  public static native @Cast("bool") boolean AttributeType_IsValid(int value);
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int AttributeType_MIN();
  public static final int AttributeType_MIN = AttributeType_MIN();
  @MemberGetter public static native @Cast("const onnx::AttributeProto::AttributeType") int AttributeType_MAX();
  public static final int AttributeType_MAX = AttributeType_MAX();
  @MemberGetter public static native int AttributeType_ARRAYSIZE();
  public static final int AttributeType_ARRAYSIZE = AttributeType_ARRAYSIZE();
  public static native @Cast("bool") boolean AttributeType_Parse(@StdString BytePointer name,
        @Cast("onnx::AttributeProto::AttributeType*") IntPointer value);
  public static native @Cast("bool") boolean AttributeType_Parse(@StdString String name,
        @Cast("onnx::AttributeProto::AttributeType*") IntBuffer value);
  public static native @Cast("bool") boolean AttributeType_Parse(@StdString BytePointer name,
        @Cast("onnx::AttributeProto::AttributeType*") int... value);
  public static native @Cast("bool") boolean AttributeType_Parse(@StdString String name,
        @Cast("onnx::AttributeProto::AttributeType*") IntPointer value);
  public static native @Cast("bool") boolean AttributeType_Parse(@StdString BytePointer name,
        @Cast("onnx::AttributeProto::AttributeType*") IntBuffer value);
  public static native @Cast("bool") boolean AttributeType_Parse(@StdString String name,
        @Cast("onnx::AttributeProto::AttributeType*") int... value);

  // accessors -------------------------------------------------------

  /** enum onnx::AttributeProto:: */
  public static final int
    kFloatsFieldNumber = 7,
    kIntsFieldNumber = 8,
    kStringsFieldNumber = 9,
    kTensorsFieldNumber = 10,
    kGraphsFieldNumber = 11,
    kTypeProtosFieldNumber = 15,
    kSparseTensorsFieldNumber = 23,
    kNameFieldNumber = 1,
    kSFieldNumber = 4,
    kDocStringFieldNumber = 13,
    kRefAttrNameFieldNumber = 21,
    kTFieldNumber = 5,
    kGFieldNumber = 6,
    kTpFieldNumber = 14,
    kSparseTensorFieldNumber = 22,
    kIFieldNumber = 3,
    kFFieldNumber = 2,
    kTypeFieldNumber = 20;
  // repeated float floats = 7;
  public native int floats_size();
  public native void clear_floats();
  public native float floats(int index);
  public native void set_floats(int index, float value);
  public native void add_floats(float value);

  // repeated int64 ints = 8;
  public native int ints_size();
  public native void clear_ints();
  public native @Cast("int64_t") long ints(int index);
  public native void set_ints(int index, @Cast("int64_t") long value);
  public native void add_ints(@Cast("int64_t") long value);

  // repeated bytes strings = 9;
  public native int strings_size();
  public native void clear_strings();
  public native @StdString BytePointer strings(int index);
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer mutable_strings(int index);
  public native void set_strings(int index, @StdString BytePointer value);
  public native void set_strings(int index, @StdString String value);
  public native void set_strings(int index, @Const Pointer value, @Cast("size_t") long size);
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer add_strings();
  public native void add_strings(@StdString BytePointer value);
  public native void add_strings(@StdString String value);
  public native void add_strings(@Const Pointer value, @Cast("size_t") long size);

  // repeated .onnx.TensorProto tensors = 10;
  public native int tensors_size();
  public native void clear_tensors();
  public native TensorProto mutable_tensors(int index);
  public native @Const @ByRef TensorProto tensors(int index);
  public native TensorProto add_tensors();

  // repeated .onnx.GraphProto graphs = 11;
  public native int graphs_size();
  public native void clear_graphs();
  public native GraphProto mutable_graphs(int index);
  public native @Const @ByRef GraphProto graphs(int index);
  public native GraphProto add_graphs();

  // repeated .onnx.TypeProto type_protos = 15;
  public native int type_protos_size();
  public native void clear_type_protos();
  public native TypeProto mutable_type_protos(int index);
  public native @Const @ByRef TypeProto type_protos(int index);
  public native TypeProto add_type_protos();

  // repeated .onnx.SparseTensorProto sparse_tensors = 23;
  public native int sparse_tensors_size();
  public native void clear_sparse_tensors();
  public native SparseTensorProto mutable_sparse_tensors(int index);
  public native @Const @ByRef SparseTensorProto sparse_tensors(int index);
  public native SparseTensorProto add_sparse_tensors();

  // optional string name = 1;
  public native @Cast("bool") boolean has_name();
  public native void clear_name();
  public native @StdString BytePointer name();
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer mutable_name();
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer release_name();
  public native void set_allocated_name(@StdString @Cast({"char*", "std::string*"}) BytePointer name);

  // optional bytes s = 4;
  public native @Cast("bool") boolean has_s();
  public native void clear_s();
  public native @StdString BytePointer s();
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer mutable_s();
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer release_s();
  public native void set_allocated_s(@StdString @Cast({"char*", "std::string*"}) BytePointer s);

  // optional string doc_string = 13;
  public native @Cast("bool") boolean has_doc_string();
  public native void clear_doc_string();
  public native @StdString BytePointer doc_string();
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer mutable_doc_string();
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer release_doc_string();
  public native void set_allocated_doc_string(@StdString @Cast({"char*", "std::string*"}) BytePointer doc_string);

  // optional string ref_attr_name = 21;
  public native @Cast("bool") boolean has_ref_attr_name();
  public native void clear_ref_attr_name();
  public native @StdString BytePointer ref_attr_name();
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer mutable_ref_attr_name();
  public native @StdString @Cast({"char*", "std::string*"}) BytePointer release_ref_attr_name();
  public native void set_allocated_ref_attr_name(@StdString @Cast({"char*", "std::string*"}) BytePointer ref_attr_name);

  // optional .onnx.TensorProto t = 5;
  public native @Cast("bool") boolean has_t();
  public native void clear_t();
  public native @Const @ByRef TensorProto t();
  public native TensorProto release_t();
  public native TensorProto mutable_t();
  public native void set_allocated_t(TensorProto t);
  public native void unsafe_arena_set_allocated_t(
        TensorProto t);
  public native TensorProto unsafe_arena_release_t();

  // optional .onnx.GraphProto g = 6;
  public native @Cast("bool") boolean has_g();
  public native void clear_g();
  public native @Const @ByRef GraphProto g();
  public native GraphProto release_g();
  public native GraphProto mutable_g();
  public native void set_allocated_g(GraphProto g);
  public native void unsafe_arena_set_allocated_g(
        GraphProto g);
  public native GraphProto unsafe_arena_release_g();

  // optional .onnx.TypeProto tp = 14;
  public native @Cast("bool") boolean has_tp();
  public native void clear_tp();
  public native @Const @ByRef TypeProto tp();
  public native TypeProto release_tp();
  public native TypeProto mutable_tp();
  public native void set_allocated_tp(TypeProto tp);
  public native void unsafe_arena_set_allocated_tp(
        TypeProto tp);
  public native TypeProto unsafe_arena_release_tp();

  // optional .onnx.SparseTensorProto sparse_tensor = 22;
  public native @Cast("bool") boolean has_sparse_tensor();
  public native void clear_sparse_tensor();
  public native @Const @ByRef SparseTensorProto sparse_tensor();
  public native SparseTensorProto release_sparse_tensor();
  public native SparseTensorProto mutable_sparse_tensor();
  public native void set_allocated_sparse_tensor(SparseTensorProto sparse_tensor);
  public native void unsafe_arena_set_allocated_sparse_tensor(
        SparseTensorProto sparse_tensor);
  public native SparseTensorProto unsafe_arena_release_sparse_tensor();

  // optional int64 i = 3;
  public native @Cast("bool") boolean has_i();
  public native void clear_i();
  public native @Cast("int64_t") long i();
  public native void set_i(@Cast("int64_t") long value);

  // optional float f = 2;
  public native @Cast("bool") boolean has_f();
  public native void clear_f();
  public native float f();
  public native void set_f(float value);

  // optional .onnx.AttributeProto.AttributeType type = 20;
  public native @Cast("bool") boolean has_type();
  public native void clear_type();
  public native @Cast("onnx::AttributeProto_AttributeType") int type();
  public native void set_type(@Cast("onnx::AttributeProto_AttributeType") int value);
}
