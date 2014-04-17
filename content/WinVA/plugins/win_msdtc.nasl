# DESC  : MSDTC / COM+
# AUTHOR: Fizz
# DATE  : 05/03/2006
#
# NOTES : This vulnerability check script has been completely
#         rewritten. It works :-)
#


include ('smb_func.inc');
include ("misc_func.inc");


# #############
# # VARIABLES #
# #############

global_var rpc_info, ip_address;

rpc_info = NULL;
ip_address = NULL;


# #############
# # FUNCTIONS #
# #############

function rpc_recv (socket)
{
    local_var header, body, len;
    header = recv (socket:socket, length:24, min:24);
    if (strlen(header) != 24)
        return NULL;
    len = get_word (blob:header, pos:8) - 24;
    body = recv (socket:socket, length:len, min:len);
    if (strlen(body) != len)
        return NULL;
    return header + body;
}


function Lookup (socket, type, object, interface, handle, entries)
{
    local_var data, ret, resp, obj, id, _handle, code, num_entries, pos, i;
    local_var object_id, ref_id, annotation_offset, annotation_length, tower_length, tower, annotation;

    if (isnull(object))
        obj = raw_dword (d:0);
    else
        obj = encode_uuid(uuid:object);

    if (isnull(interface))
        id = raw_dword (d:0);
    else
        id = encode_uuid(uuid:interface);

    if (isnull(handle))
        _handle = crap (data:raw_string(0), length:20);
    else
        _handle = handle;

    data = raw_dword (d:type)  + # Inquiry type 
        obj                    + # Object
        id                     + # interface
        raw_dword (d:0)        + # version option
        _handle                + # handle
        raw_dword (d:entries)  ; # Max entries

    ret = dce_rpc_request (code:0x02, data:data);
    send (socket:socket, data:ret);
    resp = rpc_recv (socket:socket);
    resp = dce_rpc_parse_response (data:resp);

    if (strlen (resp) < 28)
       return NULL;

    code = get_dword (blob:resp, pos:strlen(resp)-4);
    if (code != 0)
       return NULL;

    _handle = substr(resp, 0, 19);
    num_entries = get_dword (blob:resp, pos:20);

    pos = 24;
    if (num_entries > 0)
    {
        pos += 12; # actual count, offset, max count
    }

    ref_id = object_id = annotation = NULL;

    for (i=0 ; i<num_entries; i++)
    {
        if (strlen(resp) < pos + 40)
            return NULL;

        object_id[i] = substr(resp, pos, pos+15);
        ref_id[i] = get_dword (blob:resp, pos:pos+16);
        annotation_offset = get_dword (blob:resp, pos:pos+20);
        annotation_length = get_dword (blob:resp, pos:pos+24);
        annotation[i] = get_string (blob:substr(resp, pos+28, pos+28+annotation_length-1), pos:0);

        pos = pos + 28;
        if (annotation_length != 0)
        {
            pos += annotation_length;
            if (annotation_length % 4)
                pos += 4 - (annotation_length % 4);
        }
    }

    ret = NULL;
    ret[0] = _handle;

    for (i=0; i<num_entries;i++)
    {
        if (ref_id[i] != 0)
        {
            if (strlen(resp) < pos + 8)
                return NULL;

            tower_length = get_dword (blob:resp, pos:pos);
            if (tower_length > 0)
            {
                pos += 8;

                if (strlen(resp) < pos + tower_length)
                    return NULL;

                tower = substr (resp, pos, pos + tower_length - 1);
                ret[i+1] = raw_dword (d:strlen(annotation[i])) + annotation[i] + object_id[i] + tower;
                pos += tower_length;
                if (tower_length % 4)
                    pos += 4 - (tower_length % 4);
            }
        }
    }

    return ret;
}


function parse_lookup_result(data)
{
    local_var ret, num, pos, len, i, oldpos;
    ret = NULL;
    len = get_dword (blob:data, pos:0);
    if (len > 0)
        ret[1] = substr (data, 4, 4+len-1);
    else
        ret[1] = NULL;
    pos = 4 + len;
    if (strlen (data) < (pos + 18))
        return NULL;
    ret[0] = decode_uuid(uuid:substr(data,pos,pos+15));
    num = get_word (blob:data, pos:pos+16);
    pos = pos + 18;

    for (i=0; i<num; i++)
    {
        oldpos = pos;
        if (strlen (data) < pos + 2)
            return NULL;
        len = get_word (blob:data, pos:pos);
        pos += 2;
        if (strlen (data) < pos + len + 2)
            return NULL;
        pos += len;
        len = get_word (blob:data, pos:pos);
        pos += 2 + len;
        if (strlen (data) < pos)
            return NULL;
        ret[i+2] = substr(data, oldpos, pos-1);
    }
    return ret;
}


# Decodes entry and returns port / uuid...
function decode_entry (entry)
{
    local_var len, len2, part1, part2, protocol, ret, tmp, desc, port;

    len = get_word (blob:entry, pos:0);
    part1 = substr(entry, 2, 2+len-1);
    len2 = get_word (blob:entry, pos:2+len);
    part2 = substr(entry, 4+len,3+len+len2);

    ret = NULL;
    protocol = ord(part1[0]);
    ret[0] = protocol;

    # uuid
    if (protocol == 0x0d)
    {
        if (strlen(part1) < 19)
            return NULL;

        tmp = decode_uuid (uuid:substr(part1, 1, 16));
        ret[1] = "Fizz";
        ret[2] = tmp;
        return ret;
    }

    # TCP/UDP port
    if ((protocol == 0x07) || (protocol == 0x08))
    {
        port = ord(part2[0])*256 + ord(part2[1]);
        ret[1] = "Fizz";
        ret[2] = port;
        return ret;
    }

    return NULL;
}


# #############
# # THE CHECK #
# #############

# Prep for port search...

port = 135;

if (!get_port_state(port))
    exit (0);
soc = open_sock_tcp(port);
if (!soc)
    exit (0);

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"e1af8308-5d1f-11c9-91a4-08002b14a0fa", vers:3);
send (socket:soc, data:ret);
resp = rpc_recv (socket:soc);

if (!resp)
{
    close (soc);
    exit (0); 
}

ret = dce_rpc_parse_bind_ack (data:resp);
if (isnull (ret) || (ret != 0))
{
    close (soc);
    exit (0);
}

handle = NULL;
end = 0;
found = 0;

while (!end)
{
    values = Lookup (socket:soc, type:0, object:NULL, interface:NULL, handle:handle, entries:10);
    if (!isnull(values))
    {
        k++;
        handle = values[0];
        if (handle == crap(data:raw_string(0), length:20))
            end = 1;

        for (i=1; i<max_index(values); i++)
        {
            ret = parse_lookup_result (data:values[i]);
            if (!isnull(ret))
            {
                if (max_index(ret) >= 6)
                {
                    entry1 = decode_entry (entry:ret[2]);
                    entry4 = decode_entry (entry:ret[5]);

                    if ((!isnull(entry1) && !isnull(entry4)) && (entry4[0] == 0x07) && (entry1[2] == "906b0ce0-c70b-1067-b317-00dd010662da"))
                    {
                        port = entry4[2];
                        context_handles[found] = ret[0];
                        found = found + 1;
                    }
                }
            }
        }
    }
    else
        break;
}


# Test for the vulnerability...

if (!port)
    exit (0);

if (!get_port_state (port))
    exit (0);

if (isnull(context_handles))
    exit (0);

foreach context_handle (context_handles)
{
    if (!isnull(context_handle))
        break;
}

if (!get_port_state(port))
    exit(0);
soc = open_sock_tcp (port);
if (!soc)
    exit(0);

host_ip = get_host_ip();

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"906b0ce0-c70b-1067-b317-00dd010662da", vers:1);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

if (!resp)
{
    close (soc);
    exit (0); 
}

ret = dce_rpc_parse_bind_ack (data:resp);
if (isnull (ret) || (ret != 0))
{
    close (soc);
    exit (0);
}

session_set_unicode (unicode:1);

data = raw_dword (d:0) +

# Type 1
raw_dword (d:0) +       
raw_dword (d:0) +       
raw_dword (d:0) +       
raw_dword (d:0) + 
raw_dword (d:0) +       
raw_dword (d:0) +

# need a valid context handle to pass the first check
class_name (name:context_handle) +
# a patched version will first check if the length is less than 0x0F
class_name (name:crap(data:"B", length:17)) +

# need to be 37 bytes long to be a valid RPC packet
# [size_is(37)] [in]  [string] wchar_t * element_57,
# [size_is(37)] [in]  [string] wchar_t * element_58,
class_name (name:crap(data:"A", length:36)) +
class_name (name:crap(data:"A", length:36)) +

class_name (name:"tns") +

# Type 2
raw_dword (d:0) + 
raw_dword (d:0) + 
raw_dword (d:0) +

# [in]  [range(8,8)] long  element_65,
# [size_is(element_65)] [in]  char  element_66,
# range restriction is only present in the Windows XP/2003 version
raw_dword (d:8) +
raw_dword (d:8) +
crap (data:raw_string(0), length:8);

ret = dce_rpc_request (code:0x07, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);
resp = dce_rpc_parse_response (data:resp);

if (strlen(resp) > 8)
{
    val = get_dword (blob:resp, pos:strlen(resp)-4);
    if (val == 0x80070057)
    {
        if (strlen(resp) < 16)
            exit (0);

        len = get_dword (blob:resp, pos:0);
        offset = get_dword (blob:resp, pos:4);
        actual_len = get_dword (blob:resp, pos:8);

        uuid = get_string2 (blob:resp, pos:12, len:len*2);
        # a vulnerable version reply with an uuid of 000...
        # a patched version with our original buffer (tns)
        if (uuid == "00000000-0000-0000-0000-000000000000")
            display("Success");
    }
}
