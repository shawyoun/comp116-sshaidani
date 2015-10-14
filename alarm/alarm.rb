# Shawyoun Shaidani
# Comp 116, Assignment 2: Incident Alarm

require 'packetfu'
$incident_counter = 0

# Once we have a TCP packet, check for certain flags
def detectTCPIncident(pkt)
	flags = pkt.tcp_flags
	ipSrc = pkt.ip_saddr()
	
	if flags.to_i == 0
		alert("NULL scan", ipSrc, "TCP", pkt.payload)
	else
		if flags.to_i == 1
			alert("FIN scan", ipSrc, "TCP",  pkt.payload)
		elsif flags.psh == 1 && flags.urg == 1
			alert("XMAS scan", ipSrc, "TCP",  pkt.payload)
		end
	end
end

# Use regular expressions from sans.org
def findCreditCard(pkt)
	payload = pkt.payload
	if /4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match(payload) || /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match(payload) || /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match(payload) || /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/.match(payload)
		alert("Credit card leak", pkt.ip_saddr(), "HTTP", payload)
	end
end

# Listen to live packets, dispatching as needed
def sniff()
	stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)

	nmap_string = /\x4E\x6D\x61\x70/
	nikto_string = /\x4E\x69\x6B\x74\x6F/

	stream.stream.each do |raw_pkt|
		pkt = PacketFu::Packet.parse(raw_pkt)
		if pkt.is_ip? 
			if pkt.is_tcp?
				detectTCPIncident(pkt)
			end

			if nmap_string.match(pkt.payload)
				alert("Nmap scan", pkt.ip_saddr(), "TCP", pkt.payload)
			end
			
			if nikto_string.match(pkt.payload)
				alert("Nikto scan", pkt.ip_saddr(), "TCP", pkt.payload)
			end

			findCreditCard(pkt)
		end
	end
end

# Return the kind of incident in a particular line
def detectWebServerIncident(raw_line)
	if raw_line.include? "Nmap"
		return "Nmap scan"
	elsif raw_line.include? "Nitko"
		return "Nitko scan"
	elsif raw_line.include? "masscan"
		return "Mass scan"
	elsif raw_line.include? "() { :; };"
		return "Shell shock vulnerability scan"
	elsif raw_line.include? "phpmyadmin"
		return "phpMyAdmin request"
	elsif /\\x\S*\\x\S*/.match(raw_line)
		return "Shell code"
	else
		return nil
	end
end

# Split the Combined Log Format
def parseWebServerLine(raw_line)
	tokens = /^(\S+) (\S+) (\S+) \[(\S+ \+\d{4})\] "(\S+ \S+ [^"]+)" (\d{3}) (\d+|-) "(.*?)" "([^"]+)"$/.match(raw_line).to_a
	return tokens
end

# Sounds the alarm
def alert(incident, sourceIP, protocol, payload)
	$incident_counter = $incident_counter + 1
	puts $incident_counter.to_s + " : ALERT: " + incident + " is detected from " + sourceIP.to_s + " (" + protocol + ") (" + payload + ")!"

end

# Read line by line
def readLogFile(file_name)
	File.open(file_name).each do |line|
		parsedLine = parseWebServerLine(line)
		if (!parsedLine.nil? && !parsedLine.empty?)
			if detectWebServerIncident(parsedLine[0])
				alert(detectWebServerIncident(parsedLine[0]), parsedLine[1], "HTTP", parsedLine[5])
			end
		else
			puts "Could not read line."
		end
	end
end

# The code to handle the arguments

if ARGV.length == 0
	sniff()
elsif ARGV.length == 2 && ARGV[0] == "-r" && ARGV[1] =~ /\S*.log/
	readLogFile(ARGV[1])
else
	puts "Invalid arguments."
end

 
