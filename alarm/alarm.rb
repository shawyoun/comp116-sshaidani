require 'packetfu'
$incident_counter = 0

def detectTCPIncident(pkt)
	flags = pkt.tcp_flags
	ipSrc = pkt.ip_src()
	
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


def findCreditCard(pkt)
	payload = pkt.payload
	if /4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match(payload) || /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match(payload) || /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match(payload) || /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/.match(payload)
		alert("Credit card leak", pkt.ip_src, "HTTP", payload)
	end
end

def sniff()
	stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)

	nmap_string = "Nmap".each_byte.map { |b| sprintf(" 0x%02x ", b) }.join
	nikto_string = "nikto".each_byte.map { |b| sprintf(" 0x%02x ", b) }.join

	stream.stream.each do |raw_pkt|
		pkt = PacketFu::Packet.parse(raw_pkt)
		if pkt.is_ip? 
			if pkt.is_tcp?
				detectTCPIncident(pkt)
			end

			if (pkt.hexify(pkt.payload)).include? nmap_string
				alert("Nmap scan", pkt.ip_src(), "TCP", pkt.payload)
			end
			
			if (pkt.hexify(pkt.payload)).include? nikto_string
				alert("Nikto scan", pkt.ip_src(), "TCP", pkt.payload)
			end

			findCreditCard(pkt)
		end
	end
end

def detectWebServerIncident(raw_line)
	if raw_line.include? "Nmap"
		return "Nmap scan"
	elsif raw_line.include? "nitko"
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

def parseWebServerLine(raw_line)
	tokens = /^(\S+) (\S+) (\S+) \[(\S+ \+\d{4})\] "(\S+ \S+ [^"]+)" (\d{3}) (\d+|-) "(.*?)" "([^"]+)"$/.match(raw_line).to_a
	return tokens
end

def alert(incident, sourceIP, protocol, payload)
	$incident_counter = $incident_counter + 1
	puts $incident_counter.to_s + " : ALERT: " + incident + " is detected from " + sourceIP.to_s + " (" + protocol + ") (" + payload + ")!"

end

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

if ARGV.length == 0
	sniff()
elsif ARGV.length == 2 && ARGV[0] == "-r" && ARGV[1] =~ /\S*.log/
	readLogFile(ARGV[1])
else
	puts "Invalid arguments."
end

 
