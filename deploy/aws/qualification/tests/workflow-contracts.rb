#!/usr/bin/env ruby
require "yaml"

workflow = YAML.load_file(ARGV.fetch(0))
job = workflow.fetch("jobs").fetch("qualify")
raise "job timeout drift" unless job.fetch("timeout-minutes") == 120
raise "remote ceiling drift" unless job.fetch("env").fetch("Q124_SSM_MAX_EXECUTION_TIMEOUT_SECONDS") == "4200"
steps = job.fetch("steps")
by_name = steps.filter_map { |step| [step["name"], step] if step["name"] }.to_h
assume = by_name.fetch("Assume dedicated qualification identity")
raise "initial session is not 7200 seconds" unless assume.fetch("with").fetch("role-duration-seconds") == 7200
deadline = by_name.fetch("Reserve an absolute operation deadline").fetch("run")
raise "operation deadline is not bounded inside the 120-minute session" unless deadline.include?("now + 6900")
execute = by_name.fetch("Execute exact lifecycle transition").fetch("run")
raise "lifecycle does not enter the manifest-bound bundle" unless execute.include?("q124-bundle-exec.sh")

cleanup = workflow.fetch("jobs").fetch("cleanup_failed_provision")
raise "cleanup is not independent from qualification" unless cleanup.fetch("needs") == "qualify"
condition = cleanup.fetch("if")
raise "cleanup does not survive failed/cancelled qualification" unless condition.include?("always()") && condition.include?("needs.qualify.result != 'success'")
raise "cleanup timeout is not independently bounded" unless cleanup.fetch("timeout-minutes") == 120
raise "cleanup unexpectedly preserves the failed job's reserve" unless cleanup.fetch("env").fetch("Q124_CLEANUP_RESERVE_SECONDS") == "0"
cleanup_steps = cleanup.fetch("steps")
cleanup_by_name = cleanup_steps.filter_map { |step| [step["name"], step] if step["name"] }.to_h
checkout = cleanup_steps.find { |step| step["uses"] == "actions/checkout@v4" }
raise "independent cleanup does not check out the failed run SHA" unless checkout&.fetch("with")&.fetch("ref") == "${{ github.sha }}"
fresh = cleanup_by_name.fetch("Assume fresh cleanup identity")
raise "fresh cleanup session is not 120 minutes" unless fresh.fetch("with").fetch("role-duration-seconds") == 7200
cleanup_deadline = cleanup_by_name.fetch("Bound the independent cleanup session").fetch("run")
raise "cleanup deadline is not bounded inside its fresh session" unless cleanup_deadline.include?("now + 6900")
recover = cleanup_by_name.fetch("Recover failed provision independently")
raise "independent recovery mode missing" unless recover.fetch("run").include?("Q124_MODE=recover-provision-independent")
raise "independent cleanup still consumes qualify outputs" if recover.fetch("run").include?("needs.qualify.outputs")
puts "q124 workflow session/deadline contracts: PASS"
