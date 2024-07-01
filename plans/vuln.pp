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

  # Read file
  $win_scanner = file::read('log4jscanner-v0.5.0-windows-amd64.zip')
  $nix_scanner = file::read('log4jscanner-v0.5.0-linux-amd64.tar')
  out::message("targets are ${targets}")

  # copy scanner
  $file_results = write_file($nix_scanner, '/tmp', $final_target, { '_run_as' => 'root' })

  # $command_result = run_command('whoami', $targets)
  return $file_results
}
