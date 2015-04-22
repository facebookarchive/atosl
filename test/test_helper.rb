require 'minitest/autorun'
require 'open-uri'

class FixtureLoader

  MANIFEST = {
   "libsystem_kernel.dylib" => "https://s3-eu-west-1.amazonaws.com/test-fixtures.atosl.github.com/libsystem_kernel.dylib",
   "CrashUnityTest" => "https://s3-eu-west-1.amazonaws.com/test-fixtures.atosl.github.com/CrashUnityTest",
   "CrashUnityTest_4_6_IL2CPP_64bit_slow_and_safe" => "https://s3-eu-west-1.amazonaws.com/test-fixtures.atosl.github.com/CrashUnityTest_4_6_IL2CPP_64bit_slow_and_safe",
  }

  FIXTURE_PATH = File.join(File.dirname(File.realdirpath(__FILE__)), 'fixtures')

  def load
    fixtures = {}

    MANIFEST.each do |filename, url|
      path = fixture_path_for_filename(filename)

      unless File.exists?(path)
        puts "Downloading #{url}"
        download(url, path)
      end

      fixtures[filename] = path
    end

    fixtures
  end

  def download(url, target_path)
    File.open(target_path, "wb") do |saved_file|
      open(url, "rb") do |read_file|
        saved_file.write(read_file.read)
      end
    end
  end

  def fixture_path_for_filename(filename)
    File.join(File.dirname(File.realdirpath(__FILE__)), 'fixtures', filename)
  end
end

class MiniTest::Unit::TestCase
  def purge_disk_cache
      dir = ENV['HOME'] + '/.atosl-cache/'
      if Dir.exists?(dir)
        `rm -r #{dir}`
      end
  end

  # turn of the magic diff, because it tries to be smart
  # with the output
  # https://github.com/seattlerb/minitest/issues/494
  def mu_pp_for_diff obj
    mu_pp(obj).gsub(/\\n/, "\n")
  end
end

FIXTURES = FixtureLoader.new.load
ATOSL    =  File.join(File.dirname(File.realdirpath(__FILE__)), '..', 'atosl')

