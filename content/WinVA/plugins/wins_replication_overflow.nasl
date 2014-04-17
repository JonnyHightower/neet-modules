# DESC  : WINS Replication Overflow
# AUTHOR: J Roach
# DATE  : 27/02/2008
#
# NOTES : This vulnerability check script is based on the
#         wins_replication_overflow.nasl provided with nessus.
# OSVDB 12370 12378
# BID 11763,11922
# CVE 2004-0567, 2004-1080
# MS04-045

port = 42;

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

request = raw_string (0x00,0x00,0x00,0x29,0x00,0x00,0x78,0x00,0x00,0x00,0x00,0x00,
		      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x02,0x00,0x05,
	    	      0x00,0x00,0x00,0x00,0x60,0x56,0x02,0x01,0x00,0x1F,0x6E,0x03,
	    	      0x00,0x1F,0x6E,0x03,0x08,0xFE,0x66,0x03,0x00);

send(socket:soc, data:request);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

if (strlen(r) < 20) exit (0);

if (ord(r[6]) != 0x78) exit (0);

pointer = substr(r,16,19);

request = raw_string (0x00,0x00,0x00,0x0F,0x00,0x00,0x78,0x00) + pointer + raw_string(
		      0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00);

send(socket:soc, data:request);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

if (strlen(r) < 8) exit (0);

if (ord(r[6]) == 0x78)
    display("Success");
