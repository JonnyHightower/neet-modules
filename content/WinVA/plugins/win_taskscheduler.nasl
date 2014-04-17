# DESC  : Windows Task Scheduler
# AUTHOR: Fizz
# DATE  : 04/03/2006
#
# NOTES : This vulnerability check script has been completely
#         rewritten. It works :-)
#


include("smb_func.inc");
include("misc_func.inc");


# #############
# # VARIABLES #
# #############

global_var rpc_info, ip_address;

rpc_info = NULL;
ip_address = NULL;

bind = raw_string(0x05,0x00,0x0b,0x00,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
                  0x00,0x10,0x00,0x10,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
                  0xb0,0x52,0x8e,0x37,0xa9,0xc0,0xcf,0x11,0x82,0x2d,0x00,0xaa,0x00,0x51,0xe4,0x0f,
                  0x01,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,
                  0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00);

req = raw_string(0x05,0x00,0x00,0x83,0x10,0x00,0x00,0x00,0x5C,0x01,0x00,0x00,0x01,0x00,0x00,0x00,
                 0x34,0x01,0x00,0x00,0x00,0x00,0x03,0x00,0xB0,0x52,0x8E,0x37,0xA9,0xC0,0xCF,0x11,
                 0x82,0x2D,0x00,0xAA,0x00,0x51,0xE4,0x0F);

req2 = raw_string(0xCC,0xFD,0x12,0x00,0x43,0x00,0x00,0x00,
                  0x00,0x00,0x00,0x00,0x43,0x00,0x00,0x00,0x04,0x4e,0x45,0x53,0x53,0x55,0x53,0x03,
                  0x4e,0x45,0x53,0x53,0x55,0x53,0x4e,0x45,0x53,0x53,0x55,0x53,0x4e,0x45,0x53,0x53,
                  0x55,0x53,0x4e,0x45,0x53,0x53,0x55,0x53,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                  0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                  0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x00,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                  0x42,0x10,0x40,0x00,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x42,0x10,0x42,0x00,
                  0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x80,0x10,0x32,0x00,0x41,0x41,0x41,0x41,
                  0x41,0x41,0x41,0x41,0x42,0x42,0x42,0x00,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                  0x08,0x42,0x42,0x00,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x00,0x00,0x00,0x00,
                  0x43,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x43,0x00,0x00,0x00,0x41,0x41,0x41,0x41,
                  0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                  0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                  0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                  0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x00,0x41,0x41,0x41,0x41,
                  0x41,0x41,0x41,0x41,0x42,0x10,0x42,0x00,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                  0x42,0x10,0x42,0x00,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x00,0x10,0x32,0x00,
                  0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x42,0x00,0x41,0x41,0x41,0x41,
                  0x41,0x41,0x41,0x41,0x08,0x42,0x00,0x00,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

req += req2;


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


function Lookup(socket, type, object, interface, handle, entries)
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
        _handle = crap(data:raw_string(0), length:20);
    else
        _handle = handle;

    data = raw_dword (d:type)  + # Inquiry type 
        obj                    + # Object
        id                     + # interface
        raw_dword (d:0)        + # version option
        _handle                + # handle
        raw_dword (d:entries)  ; # Max entries

    ret = dce_rpc_request(code:0x02, data:data);
    send(socket:socket, data:ret);
    resp = rpc_recv(socket:socket);
    resp = dce_rpc_parse_response(data:resp);

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
function decode_entry(entry)
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

found = 0;
handle = NULL;
end = 0;


# Search for the port (DCE)...

while ((!end) && (found == 0))
{
    values = Lookup(socket:soc, type:0, object:NULL, interface:NULL, handle:handle, entries:10);
    if (!isnull(values))
    {
        k++;
        handle = values[0];
        if (handle == crap(data:raw_string(0), length:20))
            end = 1;

        for (i=1; i<max_index(values); i++)
        {
            ret = parse_lookup_result(data:values[i]);
            if (!isnull(ret))
            {
                if (max_index(ret) >= 6)
                {
                    entry1 = decode_entry(entry:ret[2]);
                    entry4 = decode_entry(entry:ret[5]);
                    if (entry1[2] == "378e52b0-c0a9-11cf-822d-00aa0051e40f")
                    {
                        storedport = entry4[2];
                        found = 1;
                    }
                }
            }
        }
    }
}


# Test for the vulnerability...

if (!storedport)
    exit (0);

soc = open_sock_tcp(storedport);
if (soc)
{
    send(socket:soc, data:bind);
    r = recv(socket:soc, length:64);
    if (r)
    {
        send(socket:soc, data:req);
        r = recv(socket:soc, length:64);
        if (r)
        {
            if ((ord(r[28]) == 13) && (ord(r[29]) == 19) && (ord(r[30]) == 4) )
            {
                display("Success");
                exit(0);
            }
        }
    }
}
