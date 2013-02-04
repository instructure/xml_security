require 'rubygems'
require 'spec'
require 'spec/autorun'

$:.unshift File.expand_path('../../lib', __FILE__)

require 'xml_security'

FIXTURE_PATH = File.expand_path(File.dirname(__FILE__) + '/fixtures')

def fixture_path(filename)
  "#{FIXTURE_PATH}/#{filename}"
end

TEST_KEY_PATH = File.expand_path('../ssl/testkey.pem', __FILE__)
TEST_KEY_FINGERPRINT = 'F3:01:B1:D2:3A:42:7F:72:50:4A:4F:59:8B:D0:06:C2:94:68:E8:7E'
