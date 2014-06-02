#!/usr/bin/ruby

require "daemons"

opts = {
	:app_name => "reqmon",
	:dir => "log",
	:log_output => true,
	:backtrace => true,
	:monitor => true
}

Daemons.run(File.join(File.dirname(__FILE__), "reqmon_worker.rb"), opts)

