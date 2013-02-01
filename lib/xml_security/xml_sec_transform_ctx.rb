module XMLSecurity
  class XmlSecTransformCtx < ::FFI::Struct
    layout \
      :userData,                    :pointer,        # void *
      :flags,                       :uint,
      :flags2,                      :uint,
      :enabledUris,                 :uint,
      :enabledTransforms,           XmlSecPtrList,
      :preExecCallback,             :pointer,        # xmlSecTransformCtxPreExecuteCallback
      :result,                      :pointer,        # xmlSecBufferPtr
      :status,                      :xmlSecTransformStatus,
      :uri,                         :string,
      :xptrExpr,                    :string,
      :first,                       :pointer,        # xmlSecTransformPtr
      :last,                        :pointer,        # xmlSecTransformPtr
      :reserved0,                   :pointer,        # void *
      :reserved1,                   :pointer         # void *
  end
end
