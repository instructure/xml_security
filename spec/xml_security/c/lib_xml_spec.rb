require 'spec_helper'

describe XMLSecurity::C::LibXML do
  describe 'xmlMalloc/xmlFree integration' do
    it 'does not explode' do
      some_xml_memory = XMLSecurity::C::LibXML.xmlMalloc(1024*1024*1024)
      XMLSecurity::C::LibXML.xmlFree(some_xml_memory)
    end
  end
end
