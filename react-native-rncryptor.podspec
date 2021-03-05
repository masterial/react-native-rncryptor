require "json"
package = JSON.parse(File.read('package.json'))

Pod::Spec.new do |s|
  s.name             = package['name']
  s.version          = package['version']
  s.summary          = package['description']
  s.requires_arc = true
  s.license      = 'MIT'
  s.homepage     = 'n/a'
  s.source       = { :git => "https://github.com/masterial/react-native-rncryptor" }
  s.author       = 'Masterial'
  s.source_files = 'ios/**/*.{h,m}'
  s.platform     = :ios, "10.0"
  s.dependency 'React-Core'
end
