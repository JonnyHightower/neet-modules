# Modified for NEET by Jonathan Roach from Nessus plugin ID 22194
# http://www.microsoft.com/technet/security/bulletin/ms06-040.mspx


include ('smb_func.inc');

global_var rpipe;


function NetPathCanonicalize ()
{
local_var fid, data, rep, ret;

fid = bind_pipe (pipe:"\browser",
uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3);
if (isnull (fid))
return 0;

# we initialize the buffer first
data = class_parameter (name:"m", ref_id:0x20000) +
class_name (name:"") +
raw_dword (d:20) +
class_name (name:"nessus") + # wcscpy in the buffer
raw_dword (d:1) +
raw_dword (d:0) ;


data = dce_rpc_pipe_request (fid:fid, code:0x1f, data:data);
if (!data)
return 0;

rep = dce_rpc_parse_response (fid:fid, data:data);
if (!rep || (strlen(rep) != 32))
return 0;

ret = get_dword (blob:rep, pos:strlen(rep)-4);
if ((ret != 0x84b) && (ret != 0x7b))
return 0;

# the patch should fill the buffer with 0, else it will return "nessus"
data = class_parameter (name:"m", ref_id:0x20000) +
class_name (name:"") + # the path reinitialize the buffer
raw_dword (d:20) +
class_name (name:"") +
raw_dword (d:1) +
raw_dword (d:0) ;

data = dce_rpc_pipe_request (fid:fid, code:0x1f, data:data);
if (!data)
return 0;

rep = dce_rpc_parse_response (fid:fid, data:data);
if (!rep || (strlen(rep) != 32))
return 0;

ret = get_dword (blob:rep, pos:strlen(rep)-4);
if ((ret != 0x84b) && (ret != 0x7b))
return 0;

ret = get_dword (blob:rep, pos:0);
if (ret != 20)
return 0;

ret = get_string (blob:rep, pos:4, _type:1);
if (ret == "nessus\")
return 1;

return 0;
}

name = kb_smb_name();
port = 445;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{
ret = NetPathCanonicalize ();
if (ret == 1)
   display("Success");

NetUseDel();
}
