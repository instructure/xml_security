require 'spec_helper'

describe XMLSecurity::C::LibXML do
  describe 'xmlMalloc/xmlFree integration' do
    it 'does not explode' do
      pending('it does explode')
      some_xml_memory = XMLSecurity::C::LibXML.xmlMalloc(8)
      sleep 5
      XMLSecurity::C::LibXML.xmlFree(some_xml_memory)
    end
  end
end
