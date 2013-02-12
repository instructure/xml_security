module XMLSecurity
  class DocumentDecrypter
    extend Common

    def self.decrypt(encrypted_xml, private_key)
      keys_manager = _init_keys_manager

      key = C::XMLSec.xmlSecOpenSSLAppKeyLoad(private_key, :xmlSecKeyDataFormatPem, nil, nil, nil)
      raise "failed to load private pem ley from #{private_key}" if key.null?

      key_add_result = C::XMLSec.xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(keys_manager, key)
      raise "failed to add key to keys manager" if key_add_result < 0

      doc = C::LibXML.xmlParseMemory(encrypted_xml, encrypted_xml.size)
      raise "could not parse XML document" if doc.null?

      doc_root = C::LibXML.xmlDocGetRootElement(doc)
      raise "could not get root element" if doc_root.null?

      start_node = C::XMLSec.xmlSecFindNode(doc_root, C::XMLSec.xmlSecNodeEncryptedData, C::XMLSec.xmlSecEncNs)
      raise "start node not found" if start_node.null?

      encryption_context = C::XMLSec.xmlSecEncCtxCreate(keys_manager)
      raise "failed to create encryption context" if encryption_context.null?

      encryption_result = C::XMLSec.xmlSecEncCtxDecrypt(encryption_context, start_node)
      raise "decryption failed" if (encryption_result < 0)

      _dump_doc(doc)
    end
  end
end
