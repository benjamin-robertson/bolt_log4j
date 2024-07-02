# This is the structure of a simple plan. To learn more about writing
# Puppet plans, see the documentation: http://pup.pt/bolt-puppet-plans

# The summary sets the description of the plan that will appear
# in 'bolt plan show' output. Bolt uses puppet-strings to parse the
# summary and parameters from the plan.
# @summary A plan created with bolt plan new.
# @param targets The targets to run on.
plan bolt_log4j::vuln (
  TargetSpec $targets,
) {
  $final_target = get_targets($targets)

  # collect facts
  run_plan('facts', 'targets' => $targets)
  $linux_targets = get_targets($targets).filter | $n | { $n.factsp['kernel'] == 'Linux' }
  $win_targets = get_targets($targets).filter | $n | { $n.factsp['kernel'] == 'Windows' }

  # Read file
  $win_scanner = file::read('bolt_log4j/log4jscanner-v0.5.0-windows-amd64.zip')
  $nix_scanner = file::read('bolt_log4j/log4jscanner-v0.5.0-linux-amd64.tar.gz')
  out::message("targets are ${targets}")

  # copy scanner
  if $win_targets.length >= 1 {
    $win_file_results = write_file($win_scanner, '/tmp/log4jscanner-v0.5.0-windows-amd64.zip', $win_targets, { '_run_as' => 'root', '_catch_errors' => true })
    $win_file_successful = $win_file_results.ok_set
    $win_file_failed = $win_file_results.error_set.names
    $win_file_eligible_targets = $win_targets - get_targets($win_file_failed)
  }
  if $linux_targets.length >= 1 {
    $linux_file_results = write_file($linux_targets, '/tmp/log4jscanner-v0.5.0-linux-amd64.tar.gz', $linux_targets, { '_run_as' => 'root', '_catch_errors' => true })
    $linux_file_successful = $linux_file_results.ok_set
    $linux_file_failed = $linux_file_results.error_set.names
    $linux_file_eligible_targets = $linux_targets - get_targets($linux_file_failed)
  }

  # $command_result = run_command('whoami', $targets)
  return $linux_file_results
}
