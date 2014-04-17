# DESC  : WINS Overflow
# AUTHOR: J Roach
# DATE  : 27/02/2008
#
# NOTES : This vulnerability check script is based on the
#         wins_overflow.nasl provided with nessus.
# BID 9624 CVE-2003-0825 OSVDB 3903
# MS04-006

port = 137;
soc = open_sock_udp(port);
if ( ! soc ) exit(0);

request = raw_string (0x83, 0x98, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		      0x3E, 0x46, 0x45, 0x45, 0x46, 0x45, 0x4f, 0x45, 0x42, 0x45, 0x43, 0x45,
                      0x4d, 0x45, 0x46 ) + crap (data:"A", length:48) +
		      crap (data:raw_string(0x3F), length:192) + 
		      raw_string (0x22) + crap (data:raw_string (0x3F), length:34) + 
                      raw_string ( 0x00, 0x00, 0x20, 0x00, 0x01); 

send(socket:soc, data:request);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

r = substr (r, 13, 17);

if ("FEEFE" >< r)
    display("Success");

