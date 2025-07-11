// Targeted by JavaCPP version 1.5.12-SNAPSHOT: DO NOT EDIT THIS FILE

package org.bytedeco.onnx;

import java.nio.*;
import org.bytedeco.javacpp.*;
import org.bytedeco.javacpp.annotation.*;

import static org.bytedeco.javacpp.presets.javacpp.*;

import static org.bytedeco.onnx.global.onnx.*;

// Run an arbitrary function on an arg
@Properties(inherit = org.bytedeco.onnx.presets.onnx.class)
public class F_Pointer extends FunctionPointer {
    static { Loader.load(); }
    /** Pointer cast constructor. Invokes {@link Pointer#Pointer(Pointer)}. */
    public    F_Pointer(Pointer p) { super(p); }
    protected F_Pointer() { allocate(); }
    private native void allocate();
    public native void call(@Const Pointer arg0);
}
