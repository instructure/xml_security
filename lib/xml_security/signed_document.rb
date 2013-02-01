module XMLSecurity
  module SignedDocument
    attr_reader :validation_error

    def self.format_cert(cert)
      # re-encode the certificate in the proper format
      # this snippet is from http://bugs.ruby-lang.org/issues/4421
      rsa = cert.public_key
      modulus = rsa.n
      exponent = rsa.e
      oid = OpenSSL::ASN1::ObjectId.new("rsaEncryption")
      alg_id = OpenSSL::ASN1::Sequence.new([oid, OpenSSL::ASN1::Null.new(nil)])
      ary = [OpenSSL::ASN1::Integer.new(modulus), OpenSSL::ASN1::Integer.new(exponent)]
      pub_key = OpenSSL::ASN1::Sequence.new(ary)
      enc_pk = OpenSSL::ASN1::BitString.new(pub_key.to_der)
      subject_pk_info = OpenSSL::ASN1::Sequence.new([alg_id, enc_pk])
      base64 = Base64.encode64(subject_pk_info.to_der)

      # This is the equivalent to the X.509 encoding used in >= 1.9.3
      "-----BEGIN PUBLIC KEY-----\n#{base64}-----END PUBLIC KEY-----"
    end

    def validate(idp_cert_fingerprint, logger = nil)
      # get cert from response
      base64_cert = self.find_first("//ds:X509Certificate", Onelogin::NAMESPACES).content
      cert_text = Base64.decode64(base64_cert)
      cert = OpenSSL::X509::Certificate.new(cert_text)

      # check cert matches registered idp cert, unless we explicitly skip this check
      unless idp_cert_fingerprint == '*'
        fingerprint = Digest::SHA1.hexdigest(cert.to_der)
        expected_fingerprint = idp_cert_fingerprint.gsub(":", "").downcase
        if fingerprint != expected_fingerprint
          @validation_error = "Invalid fingerprint (expected #{expected_fingerprint}, got #{fingerprint})"
          return false
        end
      end

      # create a copy of the document with the certificate removed
      doc = LibXML::XML::Document.new
      doc.root = doc.import(self.root)
      sigcert = doc.find_first("//ds:Signature/ds:KeyInfo", Onelogin::NAMESPACES)
      sigcert.remove!

      # validate it!
      validate_doc(doc.to_s(:indent => false), SignedDocument.format_cert(cert))
    end

    def validate_doc(xml, pem)
      kmgr = nil
      ctx = nil
      result = false

      begin
        # set up the keymgr
        kmgr = XMLSecurity.xmlSecKeysMngrCreate
        raise "failed initializing key mgr" if XMLSecurity.xmlSecOpenSSLAppDefaultKeysMngrInit(kmgr) < 0
        key = XMLSecurity.xmlSecOpenSSLAppKeyLoadMemory(pem, pem.length, :xmlSecKeyDataFormatPem, nil, nil, nil)
        raise "failed loading key" if key.null?
        raise "failed adding key to mgr" if XMLSecurity.xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(kmgr, key) < 0

        # parse the xml
        doc = XMLSecurity.xmlSecParseMemory(xml, xml.length, 0)
        root = XMLSecurity.xmlDocGetRootElement(doc)

        # add the ID attribute as an id. yeah, hacky
        idary = FFI::MemoryPointer.new(:pointer, 2)
        idary[0].put_pointer(0, FFI::MemoryPointer.from_string("ID"))
        idary[1].put_pointer(0, nil)
        XMLSecurity.xmlSecAddIDs(doc, root, idary)

        # get the root node, and then find the signature
        node = XMLSecurity.xmlSecFindNode(root, "Signature", "http://www.w3.org/2000/09/xmldsig#")
        raise "Signature node not found" if node.null?

        # create the sig context
        ctx = XMLSecurity.xmlSecDSigCtxCreate(kmgr)
        raise "failed creating digital signature context" if ctx.null?

        # verify!
        raise "failed verifying dsig" if XMLSecurity.xmlSecDSigCtxVerify(ctx, node) < 0
        result = ctx[:status] == :xmlSecDSigStatusSucceeded
        @validation_error = ctx[:status].to_s unless result
      rescue Exception => e
        @validation_error = e.message
      ensure
        XMLSecurity.xmlSecDSigCtxDestroy(ctx) if ctx
        XMLSecurity.xmlFreeDoc(doc) if doc
        XMLSecurity.xmlSecKeysMngrDestroy(kmgr) if kmgr
      end

      result
    end

    # replaces EncryptedData nodes with decrypted copies
    def decrypt!(settings)
      if settings.encryption_configured?
        find("//xenc:EncryptedData", Onelogin::NAMESPACES).each do |node|
          decrypted_xml = decrypt_node(settings, node.to_s)
          if decrypted_xml
            decrypted_doc = LibXML::XML::Document.string(decrypted_xml)
            decrypted_node = decrypted_doc.root
            decrypted_node = self.import(decrypted_node)
            node.parent.next = decrypted_node
            node.parent.remove!
          end
        end
      end
      true
    end

    def decrypt_node(settings, xmlstr)
      kmgr = nil
      ctx = nil
      doc = nil
      result = nil
      begin
        kmgr = XMLSecurity.xmlSecKeysMngrCreate
        raise "Failed initializing key mgr" if XMLSecurity.xmlSecOpenSSLAppDefaultKeysMngrInit(kmgr) < 0

        key = XMLSecurity.xmlSecOpenSSLAppKeyLoad(settings.xmlsec_privatekey, :xmlSecKeyDataFormatPem, nil, nil, nil)
        raise "Failed loading key" if key.null?
        raise "Failed adding key to mgr" if XMLSecurity.xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(kmgr, key) < 0

        doc = XMLSecurity.xmlSecParseMemory(xmlstr, xmlstr.length, 0)
        raise "Failed to parse node" if doc.null?

        ctx = XMLSecurity.xmlSecEncCtxCreate(kmgr)
        raise "failed creating enc ctx" if ctx.null?

        node = XMLSecurity.xmlDocGetRootElement(doc)
        raise "failed decrypting" if XMLSecurity.xmlSecEncCtxDecrypt(ctx, node) < 0

        ptr = FFI::MemoryPointer.new(:pointer, 1)
        sizeptr = FFI::MemoryPointer.new(:pointer, 1)
        XMLSecurity.xmlDocDumpFormatMemory(doc, ptr, sizeptr, 0)
        strptr = ptr.read_pointer
        result = strptr.null? ? nil : strptr.read_string
      rescue Exception => e
        @logger.warn "Could not decrypt: #{e.message}" if @logger
      ensure
        XMLSecurity.xmlSecEncCtxDestroy(ctx) if ctx
        XMLSecurity.xmlFreeDoc(doc) if doc
        XMLSecurity.xmlSecKeysMngrDestroy(kmgr) if kmgr
      end
      result
    end
  end
end
