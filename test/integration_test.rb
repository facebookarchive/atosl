require_relative 'test_helper'

class TestAtosl < MiniTest::Unit::TestCase

  def setup
    purge_disk_cache
  end

  def test_unsorted_symbol_table_of_libsystem_kernel
    load_address     = '0x194a38000'
    symbol_address   = '0000000194a53270'
    cmd              = "#{ATOSL} --no-cache -A arm64 -l #{load_address} -o '#{FIXTURES['libsystem_kernel.dylib']}' #{symbol_address} 2>&1"
    expected         = '__pthread_kill (in libsystem_kernel.dylib) + 33488904'
    actual           = `#{cmd}`.chomp

    assert_equal(expected, actual)
  end

  # A symboltable might contain several symbols with the same address
  # Always take the first one. This is way we need a stable sort for
  # the symbols in the symbol table. Example:
  #
  # m_UnityEngine...
  # m_41
  def test_subprogram_always_take_the_first_symbol
    load_address     = '0x9d000'
    symbol_address   = '0x003d6880'
    cmd              = "#{ATOSL} --no-cache -A armv7 -l #{load_address} -o '#{FIXTURES['CrashUnityTest']}' #{symbol_address} 2>&1"
    expected         = 'm_UnityEngine_EventSystems_ExecuteEvents_Execute_UnityEngine_EventSystems_IPointerClickHandler_UnityEngine_EventSystems_BaseEventData (in CrashUnityTest) + 3358836'
    actual           = `#{cmd}`.chomp

    assert_equal(expected, actual)
  end

  def test_unity_il2cpp_subprograms_always_take_the_first_symbol
    load_address     = '0x1000ec000'
    symbol_address   = '0x00000001007e0844'
    cmd              = "#{ATOSL} --no-cache -A arm64 -l #{load_address} -o '#{FIXTURES['CrashUnityTest_4_6_IL2CPP_64bit_slow_and_safe']}' #{symbol_address} 2>&1"
    expected         = 'FMOD::Thread::callback (in CrashUnityTest_4_6_IL2CPP_64bit_slow_and_safe) + 489640'
    actual           = `#{cmd}`.chomp

    assert_equal(expected, actual)
  end

  # IL2CPP introduces weird mangling issues but we are consistent with apple's atos
  # on this one
  # Different behavior between OSX and Linux
  # Going with the Linux behavior
  def test_unity_il2cpp_user_scripts
    load_address     = '0x1000ec000'
    symbol_address   = '0x0000000100103160'
    cmd              = "#{ATOSL} --no-cache -A arm64 -l #{load_address} -o '#{FIXTURES['CrashUnityTest_4_6_IL2CPP_64bit_slow_and_safe']}' #{symbol_address} 2>&1"
    #FIXME: On OSX a dfferent source file might be returned. However
    # This is not important, since the main target is LINUX. If we'd be running
    # on OSX, we could use the apple atos anyway
    expected = if(/darwin/ =~ RUBY_PLATFORM) != nil
      'AssemblyU002DCSharp_ButtonControllerScript_m_finallyDoTheCrash (in Bulk_Assembly-CSharp_0.cpp) (Bulk_Assembly-CSharp_0.cpp:245)'
    else
      'AssemblyU002DCSharp_ButtonControllerScript_m_finallyDoTheCrash (in CrashUnityTest_4_6_IL2CPP_64bit_slow_and_safe) (Bulk_Assembly-CSharp_0.cpp:245)'
    end

    actual           = `#{cmd}`.chomp

    assert_equal(expected, actual)
  end

  def test_subprograms_returns_the_same_result_when_using_cache
    load_address     = '0x1000ec000'
    symbol_address   = '0x00000001007e0844'
    cmd              = "#{ATOSL} -A arm64 -l #{load_address} -o '#{FIXTURES['CrashUnityTest_4_6_IL2CPP_64bit_slow_and_safe']}' #{symbol_address} 2>&1"

    # the cache is populated during the first run
    without_cache    = `#{cmd}`.chomp
    with_cache       = `#{cmd}`.chomp

    assert_equal(without_cache, with_cache)
  end

end
