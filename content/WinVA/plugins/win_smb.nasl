# DESC  : IIS Remote Command Execution
# AUTHOR: Fizz
# DATE  : 17/03/2006
#
# NOTES : This vulnerability check is based on the
#         smb_kb896422.nasl script provided from the
#         nessus project.
#


include("smb_func.inc");


# #############
# # FUNCTIONS #
# #############


global_var mpc, mdc;

function smb_trans_and_x2 (extra_parameters, transname, param, data, max_pcount)
{
    local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen, pad2;
    pad = pad2 = NULL;
    if (session_is_unicode() == 1)
        pad = raw_byte (b:0);
    else
        pad2 = raw_byte (b:0);

    header = smb_header (Command: SMB_COM_TRANSACTION, Status: nt_status (Status: STATUS_SUCCESS));
    trans = cstring (string:transname);

    p_offset = 66 + strlen(trans) + strlen (extra_parameters);
    d_offset = p_offset + strlen (param);
    plen = strlen(param);
    dlen = strlen(data);
    elen = strlen(extra_parameters);

    parameters = raw_word (w:plen) +   # total parameter count
                 raw_word (w:dlen) +   # total data count
                 raw_word (w:mpc)  +   # Max parameter count
                 raw_word (w:mdc)  +   # Max data count
                 raw_byte (b:0)    +   # Max setup count
                 raw_byte (b:0)    +   # Reserved
                 raw_word (w:0)    +   # Flags
                 raw_dword (d:0)   +   # Timeout
                 raw_word (w:0)    +   # Reserved
                 raw_word (w:plen) +   # Parameter count
                 raw_word (w:p_offset) +   # Parameter offset
                 raw_word (w:dlen)     +   # Data count
                 raw_word (w:d_offset) +   # Data offset
                 raw_byte (b:elen/2)   +   # Setup count
                 raw_byte (b:0);           # Reserved
    parameters += extra_parameters; 
    parameters = smb_parameters (data:parameters);

    dat = pad +
       trans +
       pad2 +
       raw_word (w:0) +
       param +
       data;
    dat = smb_data (data:dat);
    packet = netbios_packet (header:header, parameters:parameters, data:dat);
    ret = smb_sendrecv (data:packet); 
    if (!ret)
        return NULL;
    return ret;
}


# ##############
# # THE CHECKS #
# ##############


# Initial stuff...
port = 445;
name = kb_smb_name();
if(!name)
    exit(0);
if(!get_port_state(port))
    exit(0);
soc = open_sock_tcp(port);
if(!soc)
    exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (share:"IPC$");
if (ret != 1)
{
    close (soc);
    exit (0);
}

mpc = session_get_server_max_size() / 2;
mdc = session_get_server_max_size() / 2 + 0x10;

fid = bind_pipe (pipe:"\browser", uuid:"6bffd098-a112-3610-9833-012892020162", vers:0);
if (isnull(fid))
{
    fid = bind_pipe (pipe:"\lsarpc", uuid:"12345778-1234-abcd-ef00-0123456789ab", vers:0);
    if (isnull (fid))
    {
        NetUseDel();
        exit (0);
    }
}

parameters = raw_word (w:TRANS_PIPE) +
             raw_word (w:fid);

ret = smb_trans_and_x2 (extra_parameters:parameters, transname:"\PIPE\", param:NULL, data:dce_rpc_request (code:opnum, data:NULL), max_pcount:0);

NetUseDel ();

if (strlen(ret) > 92)
  display("Success");
