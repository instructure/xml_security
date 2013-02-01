module XMLSecurity
  class XmlSecKeyReq < ::FFI::Struct
    layout \
      :keyId,                       :string,         # xmlSecKeyDataId
      :keyType,                     :uint,           # xmlSecKeyDataType
      :keyUsage,                    :uint,           # xmlSecKeyUsage
      :keyBitsSize,                 :uint,           # xmlSecSize
      :keyUseWithList,              XmlSecPtrList,
      :reserved1,                   :pointer,        # void *
      :reserved2,                   :pointer         # void *
  end
end
