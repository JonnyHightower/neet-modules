#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

It is possible to log into the remote host.

Description :

The remote host is running one of the Microsoft Windows operating
systems.  It was possible to log into it using one of the following
account :

- NULL session
- Guest account
- Given Credentials

See also :

http://support.microsoft.com/support/kb/articles/Q143/4/74.ASP
http://support.microsoft.com/support/kb/articles/Q246/2/61.ASP

Risk factor :

none";


if(description)
{
 script_id(10394);
 script_bugtraq_id(494, 990, 11199);
 script_version ("$Revision: 1.95 $");
  script_cve_id(
    "CVE-1999-0504",
    "CVE-1999-0505",
    "CVE-1999-0506",
    "CVE-2000-0222",
    "CVE-2002-1117",
    "CVE-2005-3595"
);
 name["english"] = "SMB log in";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to log into the remote host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2007 Tenable Network Security, Inc");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "cifs445.nasl", "find_service1.nasl", "logins.nasl", "smb_nativelanman.nasl");
 if ( NASL_LEVEL >= 2202 ) script_dependencies("kerberos.nasl");
 script_require_keys("SMB/name", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("global_settings.inc");




function login(lg, pw, dom, lm, ntlm)
{ 
 local_var r, soc;

 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);

 session_init(socket:soc, hostname:name);
 r = NetUseAdd(login:lg, password:pw, domain:dom, lm_hash:lm, ntlm_hash:ntlm, share:"IPC$");
 NetUseDel();

 if ( r == 1 )
  return TRUE;
 else
  return FALSE;
}



login_has_been_supplied = 0;
port = kb_smb_transport();
name = kb_smb_name();

if ( ! get_port_state(port) )
  exit(0);

soc = open_sock_tcp(port);
if ( !soc )
  exit(0);
close(soc);

for ( i = 0 ; TRUE ; i ++ )
{
 l = get_kb_item("SMB/login_filled/" + i );
 if (l)
   l = ereg_replace(pattern:"([^ ]*) *$", string:l, replace:"\1");

 p = get_kb_item("SMB/password_filled/" + i );
 if (p)
   p = ereg_replace(pattern:"([^ ]*) *$", string:p, replace:"\1");
 else
   p = "";

 d = get_kb_item("SMB/domain_filled/" + i );
 if (d)
   d = ereg_replace(pattern:"([^ ]*) *$", string:d, replace:"\1");

 if ( l )
 {
  login_has_been_supplied ++;
  logins[i] = l;
  passwords[i] = p;
  domains[i] = d;
 }
 else break;
}

smb_domain = string(get_kb_item("SMB/workgroup"));

if (smb_domain)
{
 smb_domain = ereg_replace(pattern:"([^ ]*) *$", string:smb_domain, replace:"\1");
}

hole = 0;
rand_lg = string ( "nessus", rand(), rand(), rand() ); 
rand_pw = string ( "nessus", rand(), rand(), rand() );


valid_logins   = make_list();
valid_passwords = make_list();



if ( login(lg:NULL, pw:NULL, dom:NULL) == TRUE )
 null_session = TRUE;
else
 null_session = FALSE;


if ( ! supplied_logins_only  )
{
 if ( ( login(lg:"administrator", pw:NULL, dom:NULL) == TRUE ) && ( session_is_guest() == 0 ) )
  admin_no_pw = TRUE;
 else
  admin_no_pw = FALSE;

 if ( ( login(lg:rand_lg, pw:rand_pw, dom:NULL) == TRUE ) )
 {
  any_login = TRUE;
  set_kb_item(name:"SMB/any_login", value:TRUE);
 }
 else
  any_login = FALSE;
}

supplied_login_is_correct = FALSE;

p_type = get_kb_item("SMB/password_type");

for ( i = 0 ; logins[i] && supplied_login_is_correct == FALSE ; i ++ )
{
  user_login = logins[i];
  k_password = user_password = passwords[i];
  user_domain = domains[i];

  if (p_type == 0)
  {
   lm = ntlm = NULL;
  }
  if (p_type == 1)
  {
   lm = hex2raw2(s:tolower(user_password));
   ntlm = user_password = NULL;
  }
  else if (p_type == 2)
  {
   ntlm = hex2raw2(s:tolower(user_password));
   lm = user_password = NULL;
  }

 if ((login(lg:user_login, pw:user_password, dom:user_domain, lm:lm, ntlm:ntlm) == TRUE )  && ( session_is_guest() == 0 ))
 {
  supplied_login_is_correct = TRUE;
  smb_domain = user_domain;
 }
 else
 {
  if (tolower(user_domain) != tolower(smb_domain))
  {
   if ((login(lg:user_login, pw:user_password, dom:smb_domain, lm:lm, ntlm:ntlm) == TRUE )  && ( session_is_guest() == 0 ))
   {
    supplied_login_is_correct = TRUE;
   }
  }

  if (!supplied_login_is_correct)
  {
   if ((login(lg:user_login, pw:user_password, dom:NULL, lm:lm, ntlm:ntlm) == TRUE )  && ( session_is_guest() == 0 ))
   {
    supplied_login_is_correct = TRUE;
    smb_domain = NULL;
   }
  }

 }
}


if ( null_session || supplied_login_is_correct || admin_no_pw || any_login )
{
 if ( null_session != 0 )
 {
  set_kb_item(name:"SMB/null_session_enabled", value:TRUE);
  report = string("- NULL sessions are enabled on the remote host\n");
 }

 if ( supplied_login_is_correct )
 {
  if ( ! k_password ) k_password = "";

  set_kb_item(name:"SMB/login", value:user_login);
  set_kb_item(name:"SMB/password", value:k_password);
  if ( smb_domain != NULL ) set_kb_item(name:"SMB/domain", value:smb_domain);
  report += string("- The SMB tests will be done as '", user_login, "'/'******'\n");
 }

 if ( admin_no_pw && !any_login)
 {
  set_kb_item(name:"SMB/blank_admin_password", value:TRUE);
  report += string("- The 'administrator' account has no password set\n");
  hole = 1;
  if ( supplied_login_is_correct == FALSE )
  {
  set_kb_item(name:"SMB/login", value:"administrator");
  set_kb_item(name:"SMB/password", value:"");
  set_kb_item(name:"SMB/domain", value:"");
  }
 }

 if ( any_login )
 {
  set_kb_item(name:"SMB/guest_enabled", value:TRUE);
  report += string("- Remote users are authenticated as 'Guest'\n");
  if (( supplied_login_is_correct == FALSE ) && ( admin_no_pw == 0 ))
  {
  set_kb_item(name:"SMB/login", value:rand_lg);
  set_kb_item(name:"SMB/password", value:rand_pw);
  set_kb_item(name:"SMB/domain", value:"");
  }
 }

 if (null_session)
 {
  if (( supplied_login_is_correct == FALSE ) && ( admin_no_pw == 0 ) && ( any_login == FALSE ))
  {
  set_kb_item(name:"SMB/login", value:"");
  set_kb_item(name:"SMB/password", value:"");
  set_kb_item(name:"SMB/domain", value:"");
  }
 }


 if ( supplied_login_is_correct == FALSE && admin_no_pw == 0 && login_has_been_supplied != 0 )
  set_kb_item(name:"HostLevelChecks/smb/failed", value:TRUE);

 if ( supplied_login_is_correct || admin_no_pwd )
  set_kb_item(name:"Host/local_checks_enabled", value:TRUE);

 
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		report);
 security_note(port:port, data:report);
}
