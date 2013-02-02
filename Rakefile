require 'rubygems'
require 'spec/rake/spectask'

Spec::Rake::SpecTask.new('spec') do |t|
  t.spec_files = FileList['spec/**/*_spec.rb']
end

task :default => :spec

namespace :gem do
  desc "clean built gem"
  task :clean do
    rm_f Dir.glob("*.gem")
  end

  desc "build the gem"
  task :build => :clean do
    sh "gem build xml_security.gemspec"
  end

  desc "push the gem"
  task :push => :build do
    sh "gem push #{Dir.glob("*.gem").first}"
  end
end
