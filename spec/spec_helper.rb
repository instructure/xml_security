require 'rubygems'
require 'spec'

$:.unshift File.expand_path('../../lib', __FILE__)

require 'xml_security'

FIXTURE_PATH = File.expand_path(File.dirname(__FILE__) + '/fixtures')

def fixture_path(filename)
  "#{FIXTURE_PATH}/#{filename}"
end

TEST_KEY = File.read(File.expand_path('../ssl/testkey.pem', __FILE__))
