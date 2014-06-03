#!/usr/bin/ruby

require "json"
require "logger"
require "thread"
require "drb"
require "timeout"
require "socket"

class UnboundHelper
	def self.get_queue
		queue = {}
		queuesize = 0

		IO.popen("/usr/sbin/unbound-control dump_requestlist") do |io|
			io.each do |l|
				queuesize += 1

				# attacks seem to use A records only, include only these for safety
				next unless l =~ /^(\s+)?\d+\s+A IN ([\w\-\.]+)\. .* iterator /

				fqdn = $2.downcase
				labels = fqdn.split(".")

				domain = labels.pop(2).join(".")
				(queue[domain] ||= []) << labels
			end
		end

		return queue, queuesize
	end

	def self.get_blocked_domains
		domains = []

		IO.popen("/usr/sbin/unbound-control list_local_zones") do |io|
			io.each do |l|
				next unless l =~ /^([\w\-\.]+)\. deny$/
				domains << $1
			end
		end

		return domains
	end

	def self.block_domain(domain)
		response = IO.popen("/usr/sbin/unbound-control local_zone %s deny" % [domain]) do |io|
			io.read
		end

		if response != "ok\n"
			LOGGER.error("Error blocking domain, unbound-control response was: %s" % [response])
			return false
		end

		return true
	end

	def self.flush_requestlist
		response = IO.popen("/usr/sbin/unbound-control flush_requestlist") do |io|
			io.read
		end

		if response != "ok\n"
			LOGGER.error("Error flushing requestlist, unbound-control response was: %s" % [response])
			return false
		end

		return true
	end
end

class QueueMonitor
	def initialize
		@hostname = Socket.gethostname
		@whitelist = Regexp.new(CONFIG[:whitelist])

		LOGGER.debug("QueueMonitor initialized")
	end

	def run
		send_blocked

		loop do
			LOGGER.debug("Processing queue")

			queue, queuesize = UnboundHelper.get_queue

			LOGGER.debug("Queue had %d entries" % [queuesize])

			blocked = analyze_queue(queue, queuesize)

			if blocked
				send_blocked
			end

			sleep 60
		end
	end

	def analyze_queue(queue, queuesize)
		blocked = false

		queue.each do |domain, items|
			next if @whitelist.match(domain)

			# unbound requestlist doesn't contain duplicate FQDNs, each entry is unique
			next if items.size < CONFIG[:block_threshold]
			next if (items.size * 100 / queuesize) < CONFIG[:block_threshold_pct]

			LOGGER.info("Suspected attack using domain %s, %d entries in queue, %d total entries in queue" % [domain, items.size, queuesize])

			if UnboundHelper.block_domain(domain)
				LOGGER.info("Blocked domain %s" % [domain])
				blocked = true

				send_mail(domain, items.first(10))
			end
		end

		UnboundHelper.flush_requestlist if blocked
		return blocked
	end

	def send_mail(domain, sample)
		subject = "Unbound reqmon blocked new domain"
		recipients = CONFIG[:email_recipients].join(" ")

		3.times do
			begin
				IO.popen("mail -s '%s' -E %s" % [subject, recipients], "w+") do |io|
					io.puts sample.collect { |i| (i+[domain]).join(".") }.join("\n")
					io.flush
				end

				LOGGER.debug("Email notify sent")
				break
			rescue
				LOGGER.error("Email delivery failed, retrying")
			end
		end
	end

	def send_blocked
		domains = UnboundHelper.get_blocked_domains

		CONFIG[:cluster].each do |host|
			begin
				Timeout.timeout 10 do
					remote = DRbObject.new_with_uri("druby://#{host}:3000")
					remote.block_domains(@hostname, domains)
					LOGGER.debug("Sent %d blocked domains to %s" % [domains.size, host])
				end
			rescue => e
				LOGGER.error("Error sending blocked domains to %s: %s" % [host, e])
			end

		end
		
		LOGGER.info("Sent blocked domains to other hosts")
	end
end

class RemoteListener
	def initialize
		@hostname = Socket.gethostname

		LOGGER.debug("RemoteListener initialized")
	end

	def block_domains(remote_hostname, domains)
		LOGGER.debug("Received remote domains from %s: %s" % [remote_hostname, domains.join(",")])

		if remote_hostname == @hostname
			LOGGER.debug("Received remote domains from self, skipping")
			return
		end

		local_blocked = UnboundHelper.get_blocked_domains
		blocked = false

		domains.each do |domain|
			next if local_blocked.include?(domain)

			if UnboundHelper.block_domain(domain)
				LOGGER.info("Blocked remote domain %s" % [domain])
				blocked = true
			end
		end
		
		UnboundHelper.flush_requestlist if blocked
	end
end

CONFIG = JSON.parse(File.read(File.join(File.dirname(__FILE__), "config.json")), symbolize_names: true)

LOGGER = Logger.new(File.join(File.dirname(__FILE__), "reqmon.log"), 10, 1024000)
LOGGER.level = CONFIG[:debug] ? Logger::DEBUG : Logger::INFO
LOGGER.info("Startup")

Thread.new do
	QueueMonitor.new.run
end

DRb.start_service("druby://0.0.0.0:3000", RemoteListener.new)
DRb.thread.join

