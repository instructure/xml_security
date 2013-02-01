# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.
#
require 'rubygems'
require 'ffi'
require 'base64'
require "xml/libxml"
require "openssl"
require "digest/sha1"

require 'xml_security/c/lib_xml'
require 'xml_security/c/xml_sec'
# require 'xml_security/c/xml_sec_app'

require 'ruby-debug'

module XMLSecurity
  def self.init
    unless initialized?
      C::LibXML.init
      C::XMLSec.init
      @initialized = true
    end
  end

  def self.initialized?
    !!@initialized
  end

  def self.sign(xml_document, private_key)
    init

    doc = C::LibXML.xmlParseFile(xml_document)
    raise "could not parse XML document" if doc.null?

    canonicalization_method_id = C::XMLSec.xmlSecTransformExclC14NGetKlass
    sign_method_id = C::XMLSec.xmlSecOpenSSLTransformRsaSha1GetKlass

    sign_node = C::XMLSec.xmlSecTmplSignatureCreate(doc, canonicalization_method_id, sign_method_id, nil)

    raise "failed to create signature template" if sign_node.null?
    C::LibXML.xmlAddChild(C::LibXML.xmlDocGetRootElement(doc), sign_node)

    # ref_node = C::XMLSec.xmlSecTmplSignatureAddReference(sign_node, C::XMLSec.xmlSecTransformSha1Id, nil, nil, nil)
    # raise "failed to add a reference" if ref_node.null?
    #
    # TO BE CONTINUED... translating from sign2.c

    _dump_doc(doc)
  end

  def self._dump_doc(doc)
    ptr = FFI::MemoryPointer.new(:pointer, 1)
    sizeptr = FFI::MemoryPointer.new(:pointer, 1)
    C::LibXML.xmlDocDumpFormatMemory(doc, ptr, sizeptr, 1)
    strptr = ptr.read_pointer
    result = strptr.null? ? nil : strptr.read_string
    puts result
  end
end
