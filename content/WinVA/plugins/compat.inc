#TRUSTED 83f59e14f1a347247ca0d894301af800ca467a7b413417d29876ce2aa15c08f78dacd721f4785fd99f01bd134023cb3aefa31c79d8db7a76d1f32c0b27797fce31ef2165e323d8d5203f94572fac5e2c9e53a606e38f536307ae606cfb6e487bae4c3c8ec8abd66c06cadedd82ccc41905010aba8bb050d8e9c1e35f7eee1bccc0d06317c6ef46ca13788de0dbc36e21e06bdcbbe95e55167662f0365e05366e3deb727085cb43feb288b2e3f071b9caba9a603274d183f24ff9749b39e4fb3ded7d1010be4a805e550d2f2b59a16c87f77e09f1699e34760ff7a83957dfcabc2505e3db9a01634d972a5394b09442218cf4788d7bd687ecdf56d183f597332bb23f5f676b43e4dc2610d88ca3668e1066cc657009e8404f3efbf09b7ee2bce28a7584bf1c35b6bbaa15801dee6bb261a6f7f35441b0134f4580ab50d345f5205e7a34ec62a21e1b57405e8f3e53ed54c9c76d9024bd6ad9dcbfb9e2b167c9485a560c206303f9c3bbd6037b6b0244c3beae0be22049a36b6eed26d694f454d85b90a3957a76b65735f75ecc273e15ba386300ca27831cf1e0fa364042e96947e7dc3631b54280c0ba41ca0748f04da0026bd26f7de0feeb165166c197ca93d43db4c8cf974b9ebb80703f6c4e4c71581c4ce686dad4dd85bb10a8471c58f02f2a8e39b8a7cb35bd7b09a9bd5d86a42b2469e6fb1878d4ec81eb70252cf43009
# 
# (C) Tenable Network Security, Inc.
#
# Redistribution and use in source, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#     This product includes software developed by Tenable Network Security
#
# Revision 1.12

#
# Backward compatibility functions
#
__desc_buf = NULL;



function cvss_vector_to_temporal_score(vector, base_score)
{
 local_var str;
 local_var Exploitability, RemediationLevel, ReportConfidence;
 local_var base;
 local_var score;
 
 str = vector;
 base_score = split(base_score, sep:'.');
 base = int(base_score[0]) * 1000 + int(base_score[1]) * 100;

 if ( "E:U/" >< str )
     Exploitability = 1176; # 0.85
 else if ( "E:POC/" >< str )
     Exploitability = 1111; # 0.9 
 else if ( "E:F/" >< str )
     Exploitability = 1052; # 0.95
 else if ( "E:H/" >< str )
     Exploitability = 1000; # 1.00
 else #if ( "E:/" >< str || "E:ND/" >< str )
     Exploitability = 1000; # 1.00

 if ( "/RL:OF/" >< str )
     RemediationLevel = 1149; # 0.87
 else if ( "/RL:TF/" >< str )
     RemediationLevel = 1111; # 0.90
 else if ( "/RL:W/" >< str )
     RemediationLevel = 1052; # 0.95
 else if ( "/RL:U/" >< str )
     RemediationLevel = 1000; # 1.00
 else #if ( "/RL:/" >< str || "/RL:ND/" >< str )
     RemediationLevel = 1000; # 1.00

 if ( "/RC:UC" >< str )
     ReportConfidence = 1111; # 0.90 
 else if ( "/RC:UR" >< str )
     ReportConfidence = 1052; # 0.95
 else if ( "/RC:C" >< str )
     ReportConfidence = 1000; # 1.00
 else #if ( "/RC:" >< str || "/RC:ND" >< str )
     ReportConfidence = 1000; # 1.00

 
 score = (base  * 1000)/Exploitability;
 score = (score * 1000)/RemediationLevel;
 score = (score * 1000)/ReportConfidence;
 if ( score % 100 >= 50) score += ( 100 - (score % 100) ); # Rounding
 if ( score / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( score % 100 >= 40) score += ( 100 - (score % 100) ); 
 }
 
 score = (score/10)*10;
 return strcat(score / 1000, ".", (score % 1000)/100);
}

function cvss_vector_to_base_score()
{
 local_var str;
 local_var c,i,a;
 local_var AccessVector, AccessComplexity, Authentication;
 local_var q,z;
 local_var cvss_score;

 str = _FCT_ANON_ARGS[0];
 if ( "AV:L/" >< str )
   AccessVector = 2532;
 else if ( "AV:A/" >< str )
   AccessVector = 1548;
 else if ( "AV:N/" >< str)
   AccessVector = 1000;
 else 
 {
   #display("Unknown CVSS access subvector (", str, ")!\n");
   return NULL;
 }

 if ( "AC:L/" >< str )
   AccessComplexity = 1408;
 else if ( "AC:M/" >< str )
   AccessComplexity = 1639;
 else if ( "AC:H/" >< str )
   AccessComplexity = 2857;
 else 
 {
   #display("Unknown CVSS access complexity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "Au:N/" >< str )
   Authentication = 1420;
 else if ( "Au:S/" >< str )
   Authentication = 1786;
 else if ( "Au:M/" >< str )
   Authentication = 2222;
 else 
 {
   #display("Unknown CVSS authentication subvector (", str, ")!\n");
   return NULL;
 }

 if ( "C:N/" >< str )
   c = 1000;
 else if ( "C:P/" >< str )
   c = 725;
 else if ( "C:C/" >< str )
   c = 340;
 else 
 {
   #display("Unknown CVSS confidentiality subvector (", str, ")!\n");
   return NULL;
 }

 if ( "I:N/" >< str )
   i = 1000;
 else if ( "I:P/" >< str )
   i = 725;
 else if ( "I:C/" >< str )
   i = 340;
 else 
 {
   #display("Unknown CVSS integrity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "/A:N" >< str )
   a = 1000;
 else if ( "/A:P" >< str )
   a = 725;
 else if ( "/A:C" >< str )
   a = 340;
 else 
 {
   #display("Unknown CVSS availability subvector (", str, ")!\n");
   return NULL;
 }

 if ( c + i + a == 3000 )
   return "0.0";

 z = (c*1000)/( (1000*1000)/i);
 z = (z*1000)/( (1000*1000)/a);
 z = 1000 - z;
 z = (1000*1000)/z;
 z = (10410*1000)/z;
 z = (z*1000)/1666;

 q = ( AccessComplexity  * 1000 ) / (( 1000 * 1000 )/Authentication );
 q = ( q * 1000 ) / ( ( 1000 * 1000 ) / AccessVector );
 q = ( 1000 * 1000 ) / q;
 q = q * 20000;
 q = q / 2500;

 z = ( z + q ) - 1500;
 z = (z * 11760)/10000;
 if ( z % 100 >= 50) z += ( 100 - (z % 100) ); # Rounding
 if ( z / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( z % 100 >= 40) z += ( 100 - (z % 100) ); 
 }
 
 z = (z/10)*10;
 cvss_score = strcat(z / 1000, ".", (z % 1000)/100);
 return cvss_score;
}



function script_set_attribute(attribute, value)
{
 local_var s, e;
 local_var i;

 if ( isnull(attribute) || isnull(value) ) return;
 value = '' + value;
 e = strlen(value);
 for ( i = 0 ; value[i] >< ' \t\n\r' && i < e ; i ++ ) { };
 for ( e = strlen(value) - 1; value[e] >< ' \t\n\r' && e > 0 ; e -- ) { };
 value = substr(value, i, e);
 if ( strlen(__desc_buf[attribute]) ) __desc_buf[attribute] += '\n';
 __desc_buf[attribute] += value;
}

function script_set_cvss_base_vector()
{
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 script_set_attribute(attribute:"cvss_vector", value:vec);
 if ( NASL_LEVEL < 4300 )
  __desc_buf["cvss_base_score"] = cvss_vector_to_base_score(vec);
}

function script_set_cvss_temporal_vector()
{
 local_var base_score;
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 script_set_attribute(attribute:"cvss_temporal_vector", value:vec);

 if ( NASL_LEVEL < 4300 )
 {
  base_score = __desc_buf["cvss_base_score"];
  if ( ! isnull(base_score) )
   script_set_attribute(attribute:"cvss_temporal_score", value:cvss_vector_to_temporal_score(vector:vec, base_score:base_score));
 }
}

function script_end_attributes()
{
 local_var r;
 local_var buf;


 if ( isnull(__desc_buf["cvss_base_score"]) && !isnull(__desc_buf["cvss_vector"]) )
  __desc_buf["cvss_base_score"] = cvss_vector_to_base_score(__desc_buf["cvss_vector"]);

 if ( !isnull(__desc_buf["cvss_base_score"]) && !isnull(__desc_buf["cvss_temporal_vector"] ) )
 {
  __desc_buf["cvss_temporal_score"] = cvss_vector_to_temporal_score(vector:__desc_buf["cvss_temporal_vector"], base_score:__desc_buf["cvss_base_score"]);
 }


 if ( isnull(__desc_buf["risk_factor"]) )
 {
  if ( isnull(__desc_buf["cvss_base_score"]) )
	__desc_buf["risk_factor"] = "None";
  else {
   if ( int(__desc_buf["cvss_base_score"]) == 10 ) __desc_buf["risk_factor"] = "Critical";
   else if ( int(__desc_buf["cvss_base_score"]) >= 7 ) __desc_buf["risk_factor"] = "High";
   else if ( int(__desc_buf["cvss_base_score"]) >= 4 ) __desc_buf["risk_factor"] = "Medium";
   else if ( int(__desc_buf["cvss_base_score"]) > 0 ) __desc_buf["risk_factor"] = "Low";
   else __desc_buf["risk_factor"] = "None";
  }
 }



 buf = "";
 r = __desc_buf["synopsis"];
 if ( strlen(r) )
 {
   buf += 'Synopsis :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["description"];
 if ( strlen(r) )
 {
   buf += 'Description :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["see_also"];
 if ( strlen(r) )
 {
   buf += 'See also :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["solution"];
 if ( strlen(r) )
 {
   buf += 'Solution :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["risk_factor"];
 if ( strlen(r) )
 {
   buf += 'Risk factor :\n\n';
   buf += r;
   r = __desc_buf["cvss_base_score"];
   if ( r ) {
	buf += " / CVSS Base Score : " + r;
	r = __desc_buf["cvss_vector"];	
	if ( r ) buf += '\n(' + r + ')\n';
    	else buf += '\n';
	if ( __desc_buf["cvss_temporal_score"] ) 
	{
	 buf += 'CVSS Temporal Score : ' + __desc_buf["cvss_temporal_score"] + '\n' + '(' + __desc_buf["cvss_temporal_vector"] + ')\n';
	}
    }
    else buf += '\n';

    r = __desc_buf["exploit_available"];
    if ( strlen(r) ) buf += 'Public Exploit Available : ' + __desc_buf["exploit_available"] + '\n';
 }
 
 if ( NASL_LEVEL < 3000 && strlen(buf) >= 3000 )
   buf = strcat(substr(buf, 0, 3000), "...");

 script_description(buf);
}


function script_osvdb_id()
{
  local_var	i;
  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"OSVDB", value: i);
}

function script_cwe_id()
{
  local_var	i;
  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"CWE", value: i);
}

function script_cvs_date()
{
  local_var	v;
  v = split(_FCT_ANON_ARGS[0], sep: ' ', keep: 0);
  if ( isnull(v) || isnull(v[1]) || v[1] !~ "^2[0-9]+/[0-9]+/[0-9]+$" ) return;
  script_set_attribute(attribute:"plugin_modification_date", value: v[1]);
}

