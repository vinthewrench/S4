Pod::Spec.new do |s|
  s.name         = "S4"
	s.version      = "2.2.0"
	s.license      = { :type => 'MIT', :file => 'LICENSE.txt' }
	s.summary      = "S4 - Security Library 4 used by 4th A Technologies, LLC."
	s.description  = <<-DESC
S4 is an extensive cross platform library of cryptographic functions that can be called from the C API. It was designed to be portable, such that it can be cross-compiled for different architectures, including OS X, IOS, Linux, Android, and Windows.
                   DESC
	s.homepage     = "https://github.com/4th-ATechnologies/S4"
	s.author    	= "4th-ATechnologies"

 	s.ios.deployment_target = '9.2'
	s.osx.deployment_target = '10.10'
#	s.tvos.deployment_target = '9.0'
#	s.watchos.deployment_target = '2.0'

	s.source = {
		:git => "https://github.com/4th-ATechnologies/S4.git",
 		:tag => s.version.to_s
	}

	s.prepare_command = 'make s4_cocoapods'
	s.osx.source_files = 'build/Release/S4.framework/Versions/A/Headers/*.h'
 	s.osx.public_header_files =  'build/Release/S4.framework/Versions/A/Headers/*.h'
 	s.osx.vendored_frameworks = 'build/Release/S4.framework'

	s.ios.source_files = 'build/Release-iphoneos/S4.framework/Headers/*.h'
 	s.ios.public_header_files =  'build/Release-iphoneos/S4.framework/Headers/*.h'
 	s.ios.vendored_frameworks = 'build/Release-iphoneos/S4.framework'

# s.xcconfig            = {
#    'FRAMEWORK_SEARCH_PATHS' => '"${PODS_ROOT}/S4"',
#    'LD_RUNPATH_SEARCH_PATHS' => '@loader_path/../Frameworks'
#  } 

  end
