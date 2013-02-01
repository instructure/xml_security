module XMLSecurity
  class XmlSecPtrList < ::FFI::Struct
    layout \
      :id,                          :string,
      :data,                        :pointer,        # xmlSecPtr*
      :use,                         :uint,
      :max,                         :uint,
      :allocMode,                   :xmlSecAllocMode
  end
end
