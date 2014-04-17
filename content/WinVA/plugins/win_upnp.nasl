# DESC  : Windows Universal PnP Vulnerabilty Check
# AUTHOR: Fizz
# DATE  : 05/03/2006
#
# NOTES : This vulnerability check script has been completely
#         rewritten. It works :-)
#


include ('smb_func.inc');


# #############
# # FUNCTIONS #
# #############


global_var rpipe;

function PNP_QueryResConfList (pipe)
{
    local_var fid, data, rep, ret;

    fid = bind_pipe (pipe:pipe, uuid:"8d9f4e40-a03d-11ce-8f69-08003e30051b", vers:1);
    if (isnull (fid))
        return 0;

    data = class_name (name:"tns") +
    raw_dword (d:0) +
    raw_dword (d:0) +
    raw_dword (d:0) +
    raw_dword (d:0) +
    raw_dword (d:0);

    data = dce_rpc_pipe_request (fid:fid, code:0x36, data:data);
    if (!data)
        return 0;

    rep = dce_rpc_parse_response (fid:fid, data:data);
    if (!rep || (strlen(rep) != 8))
        return 0;

    ret = get_dword (blob:rep, pos:4);
    if (ret != 0x05)
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

 rpipe = "\srvsvc";
 r = NetUseAdd(share:"IPC$");

if ( r == 1 )
{
 ret = PNP_QueryResConfList(pipe:rpipe);
 if (ret == 1)
 {
   display("Success");
 }

 NetUseDel();
}
