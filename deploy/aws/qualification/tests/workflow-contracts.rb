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
deadline = by_name.fetch("Reserve a fresh-session cleanup window").fetch("run")
raise "provision deadline is not 80 minutes" unless deadline.include?("now + 4800")
fresh = by_name.fetch("Refresh qualification identity for bounded cleanup")
raise "fresh identity is not unconditional for provision" unless fresh.fetch("if") == "always() && inputs.mode == 'provision'"
raise "fresh cleanup session is not 30 minutes" unless fresh.fetch("with").fetch("role-duration-seconds") == 1800
recover = by_name.fetch("Recover a failed provision with the fresh session")
raise "fresh recovery condition drift" unless recover.fetch("if") == "failure() && inputs.mode == 'provision'"
raise "fresh recovery mode missing" unless recover.fetch("run").include?("Q124_MODE=recover-provision")
raise "fresh identity must precede recovery" unless steps.index(fresh) < steps.index(recover)
puts "q124 workflow session/deadline contracts: PASS"
