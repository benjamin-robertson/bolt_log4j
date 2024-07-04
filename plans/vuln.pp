# This is the structure of a simple plan. To learn more about writing
# Puppet plans, see the documentation: http://pup.pt/bolt-puppet-plans

# The summary sets the description of the plan that will appear
# in 'bolt plan show' output. Bolt uses puppet-strings to parse the
# summary and parameters from the plan.
# @summary A plan created with bolt plan new.
# @param targets The targets to run on.
plan bolt_log4j::vuln (
  TargetSpec         $targets,
  Stdlib::Windowspath $windows_file_path = 'c:\\',
  Stdlib::Unixpath   $linux_file_path   = '/tmp'
) {
  $final_target = get_targets($targets)

  # collect facts
  run_plan('facts', 'targets' => $targets)
  $linux_targets = get_targets($targets).filter | $n | { $n.facts['kernel'] == 'Linux' }
  $win_targets = get_targets($targets).filter | $n | { $n.facts['kernel'] == 'Windows' }

  # # Read file
  # $win_scanner = file::read('bolt_log4j/log4jscanner-v0.5.0-windows-amd64.zip')
  # $nix_scanner = file::read('bolt_log4j/log4jscanner-v0.5.0-linux-amd64.tar.gz')
  # $test_file = file::read('/usr/bin/vim')
  # out::message("targets are ${targets}")

  # # copy scanner
  # if $win_targets.length >= 1 {
  #   $win_file_results = write_file($win_scanner, "${windows_file_path}/log4jscanner-v0.5.0-windows-amd64.zip", $win_targets, { '_run_as' => 'root', '_catch_errors' => true })
  #   $win_file_successful = $win_file_results.ok_set
  #   $win_file_failed = $win_file_results.error_set.names
  #   $win_file_eligible_targets = $win_targets - get_targets($win_file_failed)
  # }
  # if $linux_targets.length >= 1 {
  #   $linux_file_results = write_file($nix_scanner, "${linux_file_path}/log4jscanner-v0.5.0-linux-amd64.tar.gz", $linux_targets, { '_run_as' => 'root', '_catch_errors' => true })
  #   $linux_file_successful = $linux_file_results.ok_set
  #   $linux_file_failed = $linux_file_results.error_set.names
  #   $linux_file_eligible_targets = $linux_targets - get_targets($linux_file_failed)
  # }

  # Perform apply prep
  $prep_results = apply_prep($linux_targets, '_catch_errors' => true, '_run_as' => 'root' )
  # out::message("Prep results: ${prep_results}")

  # Apply block Linux
  $linux_apply_results = apply($linux_targets,
    '_description'  => 'extact archive',
    '_catch_errors' => true,
  '_run_as'       => 'root') {
    archive { '/tmp/log4jscanner-v0.5.0-linux-amd64.tar.gz':
      ensure       => present,
      creates      => '/tmp/log4jscanner/log4jscanner',
      source       => 'puppet:///modules/bolt_log4j/log4jscanner-v0.5.0-linux-amd64.tar.gz',
      extract_path => '/tmp',
      extract      => true,
    }

    # confirm the file is exectable by all
    file { '/tmp/log4jscanner-v0.5.0-linux-amd64.tar.gz':
      ensure => file,
      mode   => '0755',
    }
  }

  $linux_apply_okay = $linux_apply_results.ok_set.names
  $linux_apply_okay_targets = get_targets($linux_apply_okay)

  # out::message("Apply results: ${linux_apply_results}")

  $linux_vuln_results = run_command('/tmp/log4jscanner/log4jscanner /', $linux_apply_okay_targets, '_catch_errors' => true, '_run_as' => 'root' )

  out::message("vuln results ${linux_vuln_results}")

  # Get vulnerable systems
  $vulnerable_systems = $linux_vuln_results.ok_set.filter | $result | { $result.value['stdout'].length > 1 }

  # Get failed systems
  $errored_systems = $linux_vuln_results.error_set.names

  $original_errored_systems = defined('$errored_systems') ? {
    true    => $errored_systems,
    default => {},
  }

  $original_vulnerable_systems = defined('$vulnerable_systems') ? {
    true    => $vulnerable_systems,
    default => {},
  }

  $vulnerable_results = $original_vulnerable_systems.reduce({}) | $memo, $value | {
    out::message("${value.target} ${value.value['stdout']}")
    $memo + { $value.target.name => $value.value['stdout'] }
  }

  $summary_results = {
    'errored_systems'    => $original_errored_systems,
    'vulnerable_systems' => $vulnerable_results,
  }

  return $summary_results
}
