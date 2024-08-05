# @summary Bolt plan to detect hosts vulnerable to log4shell.
#
# lint:ignore:140chars
#
# @param targets The targets to run on.
# @param windows_install_path File path to install the log4j scanner on windows.
# @param linux_install_path File path to install the log4j scanner on Linux.
# @param windows_scan_path File systems path to scan on Windows. Will scan recursively from this directory.
# @param linux_scan_path File systems path to scan on Linux. Will scan recursively from this directory.
plan bolt_log4j::vuln (
  TargetSpec          $targets,
  Stdlib::Windowspath $windows_install_path = 'c:\\',
  Stdlib::Unixpath    $linux_install_path   = '/tmp',
  Stdlib::Windowspath $windows_scan_path    = 'c:\\',
  Stdlib::Unixpath    $linux_scan_path      = '/',
) {
  $final_target = get_targets($targets)

  # collect facts
  run_plan('facts', 'targets' => $targets)
  $linux_targets = get_targets($targets).filter | $n | { $n.facts['kernel'] == 'Linux' }
  $win_targets = get_targets($targets).filter | $n | { $n.facts['kernel'] == 'Windows' }

  # Perform apply prep
  apply_prep($linux_targets, '_catch_errors' => true, '_run_as' => 'root' )
  apply_prep($win_targets, '_catch_errors' => true )

  # Apply block Linux
  $linux_apply_results = apply($linux_targets,
    '_description'  => 'Extract archive on Linux',
    '_catch_errors' => true,
  '_run_as'       => 'root') {
    archive { "${linux_install_path}/log4jscanner-v0.5.0-linux-amd64.tar.gz":
      ensure       => present,
      creates      => "${linux_install_path}/log4jscanner/log4jscanner",
      source       => 'puppet:///modules/bolt_log4j/log4jscanner-v0.5.0-linux-amd64.tar.gz',
      extract_path => $linux_install_path,
      extract      => true,
    }

    # confirm the file is exectable by all
    file { '/tmp/log4jscanner/log4jscanner':
      ensure => file,
      mode   => '0755',
    }
  }

  $linux_apply_okay = $linux_apply_results.ok_set.names
  $linux_apply_okay_targets = get_targets($linux_apply_okay)
  $linux_apply_failed = $linux_apply_results.error_set.names

  # Apply block Windows
  $win_apply_results = apply($win_targets,
    '_description'  => 'Extract archive on Windows',
  '_catch_errors' => true) {
    archive { "${windows_install_path}log4jscanner-v0.5.0-windows-amd64.zip":
      ensure       => present,
      creates      => "${windows_install_path}log4jscanner\\log4jscanner.exe",
      source       => 'puppet:///modules/bolt_log4j/log4jscanner-v0.5.0-windows-amd64.zip',
      extract_path => $windows_install_path,
      extract      => true,
    }
  }

  $win_apply_okay = $win_apply_results.ok_set.names
  $win_apply_okay_targets = get_targets($win_apply_okay)
  $win_apply_failed = $win_apply_results.error_set.names

  # Run the vulnerablity scan
  $linux_vuln_results = run_command("/tmp/log4jscanner/log4jscanner ${linux_scan_path}", $linux_apply_okay_targets, '_catch_errors' => true, '_run_as' => 'root' )
  $win_vuln_results = run_command("C:\\log4jscanner\\log4jscanner.exe ${windows_scan_path}", $win_apply_okay_targets, '_catch_errors' => true )

  # Get vulnerable systems
  $vulnerable_linux_systems = $linux_vuln_results.ok_set.filter | $result | { $result.value['stdout'].length > 1 }
  $vulnerable_win_systems = $win_vuln_results.ok_set.filter | $result | { $result.value['stdout'].length > 1 }

  # Get failed systems, including those which failed the apply block
  $errored_systems = $linux_vuln_results.error_set.names + $linux_apply_failed + $win_apply_failed

  $original_errored_systems = defined('$errored_systems') ? {
    true    => $errored_systems,
    default => {},
  }

  $original_vulnerable_systems_linux = defined('$vulnerable_linux_systems') ? {
    true    => $vulnerable_linux_systems,
    default => {},
  }

  $original_vulnerable_systems_win = defined('$vulnerable_win_systems') ? {
    true    => $vulnerable_win_systems,
    default => {},
  }

  $vulnerable_results_linux = $original_vulnerable_systems_linux.reduce({}) | $memo, $value | {
    out::message("${value.target} ${value.value['stdout']}")
    $memo + { $value.target.name => split($value.value['stdout'], '\n') }
  }

  $vulnerable_results_win = $original_vulnerable_systems_win.reduce({}) | $memo, $value | {
    out::message("${value.target} ${value.value['stdout']}")
    $memo + { $value.target.name => split($value.value['stdout'], '\n') }
  }

  $vulnerable_results = $vulnerable_results_win + $vulnerable_results_linux

  $summary_results = {
    'errored_systems'          => $original_errored_systems,
    'vulnerable_systems'       => $vulnerable_results,
    'vulnerable_systems_total' => $vulnerable_results.length,
  }

  return $summary_results
}
# lint:endignore
