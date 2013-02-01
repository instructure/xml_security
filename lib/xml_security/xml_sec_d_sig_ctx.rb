module XMLSecurity
  class XmlSecDSigCtx < ::FFI::Struct
    layout \
      :userData,                    :pointer,     # void *
      :flags,                       :uint,
      :flags2,                      :uint,
      :keyInfoReadCtx,              XmlSecKeyInfoCtx.by_value,
      :keyInfoWriteCtx,             XmlSecKeyInfoCtx.by_value,
      :transformCtx,                XmlSecTransformCtx.by_value,
      :enabledReferenceUris,        :uint,        # xmlSecTransformUriType
      :enabledReferenceTransforms,  :pointer,     # xmlSecPtrListPtr
      :referencePreExecuteCallback, :pointer,     # xmlSecTransformCtxPreExecuteCallback
      :defSignMethodId,             :string,      # xmlSecTransformId
      :defC14NMethodId,             :string,      # xmlSecTransformId
      :defDigestMethodId,           :string,      # xmlSecTransformId

      :signKey,                     :pointer,     # xmlSecKeyPtr
      :operation,                   :xmlSecTransformOperation,
      :result,                      :pointer,     # xmlSecBufferPtr
      :status,                      :xmlSecDSigStatus,
      :signMethod,                  :pointer,     # xmlSecTransformPtr
      :c14nMethod,                  :pointer,     # xmlSecTransformPtr
      :preSignMemBufMethod,         :pointer,     # xmlSecTransformPtr
      :signValueNode,               :pointer,     # xmlNodePtr
      :id,                          :string,
      :signedInfoReferences,        XmlSecPtrList,
      :manifestReferences,          XmlSecPtrList,
      :reserved0,                   :pointer,
      :reserved1,                   :pointer
  end
end
