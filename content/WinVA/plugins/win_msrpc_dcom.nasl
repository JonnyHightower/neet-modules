# DESC  : Microsoft Windows DCOM
# AUTHOR: Fizz
# DATE  : 08/03/2006
#
# NOTES : This vulnerability check is based on the
#         win_msrpc_dcom2.nasl script provided from the
#         nessus project.
#

include ('smb_func.inc');

function RemoteGetClassObject ()
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\epmapper", uuid:"000001a0-0000-0000-c000-000000000046", vers:0);
 if (isnull (fid))
   return 0;

 data = raw_word (w:5) +
        raw_word (w:6) +
        raw_dword (d:1) +
        raw_dword (d:0) +
        encode_uuid (uuid:"54454e41-424c-454e-4554-574f524b5345") +
	raw_dword (d:0) +
        raw_dword (d:0x20000) +
	raw_dword (d:12) +
        raw_dword (d:12) +
	crap (data:"A", length:12) +
        raw_dword (d:0);


 data = dce_rpc_pipe_request (fid:fid, code:0x03, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 16))
   return 0;

 ret = get_dword (blob:rep, pos:strlen(rep)-4);
 if ((ret == 0x8001011d) || (ret == 0x80070057) || (ret == 0x80070005))
   return 0;

 return 1;
}

# #############
# # THE CHECK #
# #############

port = 445;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

name	= kb_smb_name();

session_init(socket:soc, hostname:name);

r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{

 ret = RemoteGetClassObject();
 if (ret == 1)
   display("Success");

 NetUseDel();
}
