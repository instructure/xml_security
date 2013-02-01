module XMLSecurity
  class XmlSecKeyInfoCtx < ::FFI::Struct
    layout \
      :userDate,                    :pointer,
      :flags,                       :uint,
      :flags2,                      :uint,
      :keysMngr,                    :pointer,
      :mode,                        :xmlSecKeyInfoMode,
      :enabledKeyData,              XmlSecPtrList,
      :base64LineSize,              :int,
      :retrievalMethodCtx,          XmlSecTransformCtx,
      :maxRetrievalMethodLevel,     :int,
      :encCtx,                      :pointer,
      :maxEncryptedKeyLevel,        :int,
      :certsVerificationTime,       :time_t,
      :certsVerificationDepth,      :int,
      :pgpReserved,                 :pointer,
      :curRetrievalMethodLevel,     :int,
      :curEncryptedKeyLevel,        :int,
      :keyReq,                      XmlSecKeyReq,
      :reserved0,                   :pointer,
      :reserved1,                   :pointer
  end
end
