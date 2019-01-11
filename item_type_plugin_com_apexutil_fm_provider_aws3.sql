prompt --application/set_environment
set define off verify off feedback off
whenever sqlerror exit sql.sqlcode rollback
--------------------------------------------------------------------------------
--
-- ORACLE Application Express (APEX) export file
--
-- You should run the script connected to SQL*Plus as the Oracle user
-- APEX_180100 or as the owner (parsing schema) of the application.
--
-- NOTE: Calls to apex_application_install override the defaults below.
--
--------------------------------------------------------------------------------
begin
wwv_flow_api.import_begin (
 p_version_yyyy_mm_dd=>'2018.04.04'
,p_release=>'18.1.0.00.45'
,p_default_workspace_id=>2000120
,p_default_application_id=>9999
,p_default_owner=>'APU'
);
end;
/
prompt --application/shared_components/plugins/item_type/com_apexutil_fm_provider_aws3
begin
wwv_flow_api.create_plugin(
 p_id=>wwv_flow_api.id(67763768571556289)
,p_plugin_type=>'ITEM TYPE'
,p_name=>'COM.APEXUTIL.FM.PROVIDER.AWS3'
,p_display_name=>'FM Provider AWS3'
,p_supported_ui_types=>'DESKTOP:JQM_SMARTPHONE'
,p_supported_component_types=>'APEX_APPLICATION_PAGE_ITEMS'
,p_plsql_code=>wwv_flow_string.join(wwv_flow_t_varchar2(
'g_amz_timestamp_format constant varchar2(33) := ''Dy, DD Mon YYYY HH24:MI:SS TZHTZM'';',
'g_amz_nls_date_language constant varchar2(8) := ''AMERICAN'';',
'g_utf8_encoding_code constant varchar2(8) := ''AL32UTF8'';',
'',
'g_amazon_url constant varchar2(13) := ''amazonaws.com'';',
'g_s3 constant varchar2(2) := ''s3'';',
'g_min_postfix constant varchar2(4) := ''.min'';',
'g_timestamp_format constant varchar2(21) := ''yyyy-mm-dd hh24:mi:ss'';',
'',
'/**',
' * https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region',
' */',
'g_us_east_n_virginia constant varchar2(9) := ''us-east-1''; --Versions 2 and 4',
'g_us_west_n_california constant varchar2(9) := ''us-west-1''; --Versions 2 and 4',
'g_us_west_oregon constant varchar2(9) := ''us-west-2''; --Versions 2 and 4',
'g_asia_pacific_singapore constant varchar2(14) := ''ap-southeast-1''; --Versions 2 and 4',
'g_asia_pacific_sydney constant varchar2(14) := ''ap-southeast-2''; --Versions 2 and 4',
'g_asia_pacific_tokyo constant varchar2(14) := ''ap-northeast-1''; --Versions 2 and 4',
'g_eu_ireland constant varchar2(9) := ''eu-west-1''; --Versions 2 and 4',
'g_south_america_sao_paulo constant varchar2(9) := ''sa-east-1''; --Versions 2 and 4',
'',
'function is_signature_v2(',
'p_region in varchar2',
')',
'return boolean as',
'begin',
'  return p_region = g_us_east_n_virginia',
'         or p_region = g_us_west_n_california',
'         or p_region = g_us_west_oregon',
'         or p_region = g_asia_pacific_singapore',
'         or p_region = g_asia_pacific_sydney',
'         or p_region = g_asia_pacific_tokyo',
'         or p_region = g_eu_ireland',
'         or p_region = g_south_america_sao_paulo;',
'end is_signature_v2;',
'',
'/**',
' * Validate plugin attributes.',
' */',
'procedure validate_attributes(',
'p_access_key_id     in varchar2',
', p_secret_access_key in varchar2',
', p_bucket            in varchar2',
', p_expires_gap       in number',
', p_region            in varchar2',
') as',
'begin',
'  -----------------------------------------',
'  -- Validate Access Key Id',
'  -----------------------------------------',
'  if p_access_key_id is null or length(p_access_key_id) = 0 then',
'    raise_application_error(-20000, ''Access Key Id is undefined.'');',
'  end if;',
'  -----------------------------------------',
'  -- Validate Secret Access Key',
'  -----------------------------------------',
'  if p_secret_access_key is null or length(p_secret_access_key) = 0 then',
'    raise_application_error(-20000, ''Secret Access Key is undefined.'');',
'  end if;',
'  -----------------------------------------',
'  -- Validate Bucket',
'  -----------------------------------------',
'  if p_bucket is null or length(p_bucket) = 0 then',
'    raise_application_error(-20000, ''Bucket is undefined.'');',
'  end if;',
'  -----------------------------------------',
'  -- Validate Expires Gap',
'  -----------------------------------------',
'  if p_expires_gap <= 0 or p_expires_gap >= 28800 then',
'    raise_application_error(-20000, ''Expires must be greater then 0 and less then 28801.'');',
'  end if;',
'  -----------------------------------------',
'  -- Validate Region',
'  -----------------------------------------',
'  if not is_signature_v2(p_region) then',
'    raise_application_error(-20000, ''Unsupported region.'');',
'  end if;',
'',
'end validate_attributes;',
'',
'/**',
' * Creates input params for JS object.',
' */',
'function create_input_params(',
'p_ajax_identifier in varchar2',
')',
'return clob as',
'l_result clob;',
'begin',
'  -----------------------------------------',
'  -- Open json',
'  -----------------------------------------',
'  apex_json.initialize_clob_output;',
'  apex_json.open_object;',
'  -----------------------------------------',
'  -- Generate ajax identifier',
'  -----------------------------------------',
'  apex_json.write(''ajaxId'', p_ajax_identifier);',
'  -----------------------------------------',
'  -- Close json',
'  -----------------------------------------',
'  apex_json.close_object;',
'  l_result := apex_json.get_clob_output;',
'  apex_json.free_output;',
'',
'  return l_result;',
'end create_input_params;',
'',
'/**',
' * Returns amazon url context.',
' * See https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheCanonicalizedResourceElement',
' * https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region',
' */',
'function get_context(',
'p_region        in varchar2',
', p_canonicalized in varchar2',
')',
'return varchar2 as',
'begin',
'  if is_signature_v2(p_region) then',
'    return ''//'' || g_s3 || ''.'' || p_region || ''.'' || g_amazon_url || p_canonicalized;',
'  else',
'    raise_application_error(-20000, ''Unsupported region.'');',
'  end if;',
'end get_context;',
'',
'/**',
' * Returns amazon request in an agreed-upon form for signing.',
' * Template: /<bucket>/<key>',
' * Template params: bucket, key',
' * See https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationRequestCanonicalization',
' */',
'function get_canonicalized_resource(',
'p_bucket in varchar2',
', p_key    in varchar2',
')',
'return varchar2',
'as',
'begin',
'  return ''/'' || p_bucket || ''/'' || p_key;',
'end get_canonicalized_resource;',
'',
'/**',
' * Returns the CanonicalizedAmzHeaders part of StringToSign.',
' * See https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationConstructingCanonicalizedAmzHeadersn',
' */',
'function get_canonicalized_headers(',
'p_date in varchar2',
')',
'return varchar2',
'as',
'begin',
'  return ''x-amz-date:'' || p_date;',
'end get_canonicalized_headers;',
'',
'function get_canonicalized(',
'p_resource in varchar2',
', p_headers  in varchar2',
')',
'return varchar2',
'as',
'begin',
'  return p_headers || chr(10) || p_resource;',
'end get_canonicalized;',
'',
'/**',
' * Returns amazon string to sign for query.',
' * Template: <method>/n/n/n<expires>/n<canonicalized>',
' * Template params: method, expires, canonicalized',
' * See https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationQueryStringAuth',
' */',
'function get_string_to_sign_for_query(',
'p_method        in varchar2',
', p_expires       in number',
', p_canonicalized in varchar2',
')',
'return varchar2 as',
'begin',
'  return p_method || chr(10) || chr(10) || chr(10) || p_expires || chr(10) || p_canonicalized;',
'end get_string_to_sign_for_query;',
'',
'/**',
' * Returns amazon string to sign for authentication.',
' * Template: <method>/n/n<type>/n<date>/n<canonicalized>',
' * Template params: method, type, date, canonicalized',
' * See https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader',
' */',
'function get_string_to_sign_for_auth(',
'p_method        in varchar2',
', p_type          in varchar2 default ''''',
', p_canonicalized in varchar2',
')',
'return varchar2 as',
'begin',
'  return p_method || chr(10) || chr(10) || p_type || chr(10) || chr(10) || p_canonicalized;',
'end get_string_to_sign_for_auth;',
'',
'/**',
' * Returns datetime string in RFC 2616 format.',
' */',
'function get_rfc_datetime_string',
'return varchar2 as',
'begin',
'  return to_char(systimestamp, g_amz_timestamp_format, ''NLS_DATE_LANGUAGE = '' || g_amz_nls_date_language);',
'end get_rfc_datetime_string;',
'',
'/**',
' * Sign string.',
' * See https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationQueryStringAuth',
' *',
' * Signature = URL-Encode( Base64( HMAC-SHA1( YourSecretAccessKeyID, UTF-8-Encoding-Of( StringToSign))));',
' * 1. Encoding of string and secret',
' * 2. Encryption of string, using secret access key id and HMAC-SHA1 algorithm',
' * 3. Translate to base64',
' */',
'function sign_string(',
'p_string_to_sign    in varchar2',
', p_secret_access_key in varchar2',
')',
'return varchar2 as',
'l_string_to_sign_utf8_raw    raw(1000);',
'l_secret_access_key_utf8_raw raw(1000);',
'l_encrypted_sgnt_raw         raw(1000);',
'l_encrypted_sgnt_base64_raw  raw(1000);',
'begin',
'  l_string_to_sign_utf8_raw := utl_i18n.string_to_raw(p_string_to_sign, g_utf8_encoding_code);',
'  l_secret_access_key_utf8_raw := utl_i18n.string_to_raw(p_secret_access_key, g_utf8_encoding_code);',
'',
'  l_encrypted_sgnt_raw := dbms_crypto.mac(l_string_to_sign_utf8_raw, dbms_crypto.HMAC_SH1,',
'                                          l_secret_access_key_utf8_raw);',
'  l_encrypted_sgnt_base64_raw := utl_encode.base64_encode(l_encrypted_sgnt_raw);',
'',
'  return utl_i18n.raw_to_char(l_encrypted_sgnt_base64_raw, g_utf8_encoding_code);',
'end sign_string;',
'',
'/**',
' * Returns query string authenticated Amazon S3 REST request.',
' * Template: ?AWSAccessKeyId=<access_key_id>&Signature=<signature>&Expires=<expires>',
' * Template params: access_key_id, signature, expires',
' * https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationQueryStringAuth',
' */',
'function get_auth_for_query(',
'p_access_key_id in varchar2',
', p_signature     in varchar2',
', p_expires       in number',
')',
'return varchar2 as',
'begin',
'  return ''?AWSAccessKeyId='' || p_access_key_id || ''&Signature='' || wwv_flow_utilities.url_encode2(p_signature) ||',
'         ''&Expires='' || p_expires;',
'end get_auth_for_query;',
'',
'/**',
' * Returns authentication header value for Amazon S3 REST request.',
' * Template: AWS <access_key_id>:<signature>',
' * Template params: access_key_id, signature',
' * https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader',
' */',
'function get_auth_for_header(',
'p_access_key_id in varchar2',
', p_signature     in varchar2',
')',
'return varchar2 as',
'begin',
'  return ''AWS '' || p_access_key_id || '':'' || p_signature;',
'end get_auth_for_header;',
'',
'/**',
' * Returns the number of seconds since the epoch (00:00:00 UTC on January 1, 1970).',
' */',
'function get_utc_unix_time',
'return number',
'as',
'begin',
'  return trunc((to_date(to_char(sys_extract_utc(systimestamp), g_timestamp_format), g_timestamp_format) -',
'                to_date(''19700101'', ''YYYYMMDD'')) * 86400);',
'end get_utc_unix_time;',
'',
'/**',
' * Returns the expires time since the epoch (00:00:00 UTC on January 1, 1970).',
' */',
'function get_expires_utc_unix_time(',
'p_expires_gap in number',
')',
'return number',
'as',
'begin',
'  return get_utc_unix_time() + p_expires_gap;',
'end get_expires_utc_unix_time;',
'',
'/**',
' * sts - string to sign',
' */',
'function ajax_upload_response(',
'p_expires_gap       in number',
', p_bucket            in varchar2',
', p_region            in varchar2',
', p_key               in varchar2',
', p_access_key_id     in varchar2',
', p_secret_access_key in varchar2',
', p_type              in varchar2',
')',
'return clob',
'as',
'l_type                   varchar2(4000) := p_type;',
'l_expires                number;',
'l_canonicalized_resource varchar2(4000);',
'l_canonicalized_headers  varchar2(4000);',
'l_canonicalized          varchar2(4000);',
'l_context                varchar2(4000);',
'l_amz_date_str           varchar2(4000);',
'',
'l_sts_get                varchar2(4000);',
'l_signature_get          varchar2(4000);',
'l_auth_get               varchar2(4000);',
'',
'l_sts_put       varchar2(4000);',
'l_signature_put varchar2(4000);',
'l_auth_put      varchar2(4000);',
'',
'l_json          clob;',
'',
'begin',
'',
'  if p_type is null or length(p_type) = 0 then',
'    l_type := ''application/octet-stream'';',
'  end if;',
'',
'  l_expires := get_expires_utc_unix_time(p_expires_gap);',
'  l_amz_date_str := get_rfc_datetime_string();',
'  ------------------------------------------------',
'  -- Canonicalization for signing',
'  ------------------------------------------------',
'  l_canonicalized_resource := get_canonicalized_resource(p_bucket, p_key);',
'  l_canonicalized_resource := utl_url.escape(l_canonicalized_resource);',
'  l_canonicalized_headers := get_canonicalized_headers(l_amz_date_str);',
'  l_canonicalized := get_canonicalized(l_canonicalized_resource, l_canonicalized_headers);',
'  ------------------------------------------------',
'  -- Context',
'  ------------------------------------------------',
'  l_context := get_context(p_region, l_canonicalized_resource);',
'  ------------------------------------------------',
'  -- Strings to sign',
'  ------------------------------------------------',
'  l_sts_get := get_string_to_sign_for_query(''GET'', l_expires, l_canonicalized_resource);',
'  l_sts_put := get_string_to_sign_for_auth(',
'      p_method => ''PUT''',
'      , p_type => l_type',
'      , p_canonicalized => l_canonicalized',
'  );',
'  ------------------------------------------------',
'  -- Signatures',
'  ------------------------------------------------',
'  l_signature_get := sign_string(l_sts_get, p_secret_access_key);',
'  l_signature_put := sign_string(l_sts_put, p_secret_access_key);',
'  ------------------------------------------------',
'  -- Auth',
'  ------------------------------------------------',
'  l_auth_get := get_auth_for_query(p_access_key_id, l_signature_get, l_expires);',
'  l_auth_put := get_auth_for_header(p_access_key_id, l_signature_put);',
'  ------------------------------------------------',
'  -- JSON',
'  ------------------------------------------------',
'  -- @formatter:off',
'      apex_json.initialize_clob_output;',
'      apex_json.open_object;',
'        apex_json.write(''success'', true);',
'        apex_json.write(''key'', p_key);',
'        apex_json.write(''url'', l_context);',
'        apex_json.write(''download'', l_context || l_auth_get);',
'',
'        apex_json.open_array(''headers'');',
'',
'          apex_json.open_object;',
'            apex_json.write(''header'', ''Content-Type'');',
'            apex_json.write(''value'', l_type);',
'          apex_json.close_object;',
'',
'          apex_json.open_object;',
'            apex_json.write(''header'', ''x-amz-date'');',
'            apex_json.write(''value'', l_amz_date_str);',
'          apex_json.close_object;',
'',
'          apex_json.open_object;',
'            apex_json.write(''header'', ''Authorization'');',
'            apex_json.write(''value'', l_auth_put);',
'          apex_json.close_object;',
'',
'        apex_json.close_array;',
'',
'      apex_json.close_object;',
'      l_json := apex_json.get_clob_output;',
'      apex_json.free_output;',
'      -- @formatter:on',
'',
'  return l_json;',
'end ajax_upload_response;',
'',
'/**',
' * sts - string to sign',
' */',
'function ajax_delete_response(',
'p_bucket            in varchar2',
', p_region            in varchar2',
', p_key               in varchar2',
', p_access_key_id     in varchar2',
', p_secret_access_key in varchar2',
')',
'return clob',
'as',
'l_amz_date_str           varchar2(4000);',
'l_canonicalized_resource varchar2(4000);',
'l_canonicalized_headers  varchar2(4000);',
'l_canonicalized          varchar2(4000);',
'l_context                varchar2(4000);',
'',
'l_sts_delete             varchar2(4000);',
'l_signature_delete       varchar2(4000);',
'l_auth_delete            varchar2(4000);',
'',
'l_json                   clob;',
'',
'begin',
'  l_amz_date_str := get_rfc_datetime_string();',
'  ------------------------------------------------',
'  -- Canonicalization for signing',
'  ------------------------------------------------',
'  l_canonicalized_resource := get_canonicalized_resource(p_bucket, p_key);',
'  l_canonicalized_resource := utl_url.escape(l_canonicalized_resource);',
'  l_canonicalized_headers := get_canonicalized_headers(l_amz_date_str);',
'  l_canonicalized := get_canonicalized(l_canonicalized_resource, l_canonicalized_headers);',
'  ------------------------------------------------',
'  -- Context',
'  ------------------------------------------------',
'  l_context := get_context(p_region, l_canonicalized_resource);',
'  ------------------------------------------------',
'  -- Strings to sign',
'  ------------------------------------------------',
'  l_sts_delete := get_string_to_sign_for_auth(',
'      p_method => ''DELETE''',
'      , p_canonicalized => l_canonicalized',
'  );',
'  ------------------------------------------------',
'  -- Signatures',
'  ------------------------------------------------',
'  l_signature_delete := sign_string(l_sts_delete, p_secret_access_key);',
'  ------------------------------------------------',
'  -- Auth',
'  ------------------------------------------------',
'  l_auth_delete := get_auth_for_header(p_access_key_id, l_signature_delete);',
'  ------------------------------------------------',
'  -- JSON',
'  ------------------------------------------------',
'  -- @formatter:off',
'      apex_json.initialize_clob_output;',
'      apex_json.open_object;',
'        apex_json.write(''success'', true);',
'        apex_json.write(''url'', l_context);',
'',
'        apex_json.open_array(''headers'');',
'          apex_json.open_object;',
'            apex_json.write(''header'', ''x-amz-date'');',
'            apex_json.write(''value'', l_amz_date_str);',
'          apex_json.close_object;',
'          apex_json.open_object;',
'            apex_json.write(''header'', ''Authorization'');',
'            apex_json.write(''value'', l_auth_delete);',
'          apex_json.close_object;',
'        apex_json.close_array;',
'',
'      apex_json.close_object;',
'      l_json := apex_json.get_clob_output;',
'      apex_json.free_output;',
'      -- @formatter:on',
'',
'  return l_json;',
'end ajax_delete_response;',
'',
'/**',
' * Returns code which create provider object.',
' */',
'function create_object_initial_code(',
'p_item_name in varchar2',
', p_js_class  in varchar2',
', p_params    in clob default ''''',
')',
'return varchar2',
'as',
'begin',
'  return',
'  ''window.FileManager=window.FileManager||{}; '' ||',
'  ''window.FileManager.providers=window.FileManager.providers||{}; '' ||',
'  ''window.FileManager.providers.'' || p_item_name || ''=new '' || p_js_class || ''('' || p_params || '');'';',
'end create_object_initial_code;',
'',
'/**',
' * Returns library name depending on the application mode.',
' */',
'function resolve_library_name(',
'p_name in varchar2',
')',
'return varchar2',
'as',
'begin',
'  if apex_application.g_debug then',
'    return p_name;',
'  else',
'    return p_name || g_min_postfix;',
'  end if;',
'end resolve_library_name;',
'',
'procedure render(',
'p_item   in            apex_plugin.t_item',
', p_plugin in            apex_plugin.t_plugin',
', p_param  in            apex_plugin.t_item_render_param',
', p_result in out nocopy apex_plugin.t_item_render_result',
') as',
'l_class                      varchar2(31) := ''window.FileManager.AWS3Provider'';',
'l_lib_provider_name constant varchar2(13) := ''aws3-provider'';',
'l_params                     clob;',
'',
'l_access_key_id              varchar2(4000) := p_item.attribute_01;',
'l_secret_access_key          varchar2(4000) := p_item.attribute_02;',
'l_bucket                     varchar2(4000) := p_item.attribute_05;',
'l_expires_gap                number := p_item.attribute_07;',
'l_region                     varchar2(4000) := p_item.attribute_08;',
'',
'begin',
'  -----------------------------------------',
'  -- Validation',
'  -----------------------------------------',
'  validate_attributes(',
'      p_access_key_id => l_access_key_id',
'      , p_secret_access_key => l_secret_access_key',
'      , p_bucket => l_bucket',
'      , p_expires_gap => l_expires_gap',
'      , p_region => l_region',
'  );',
'  -----------------------------------------',
'  -- Libraries',
'  -----------------------------------------',
'  apex_javascript.add_library(',
'      resolve_library_name(l_lib_provider_name)',
'      , p_directory => p_plugin.file_prefix',
'  );',
'  ------------------------------------------------',
'  -- Input params',
'  ------------------------------------------------',
'  l_params := create_input_params(p_ajax_identifier => apex_plugin.get_ajax_identifier);',
'  ------------------------------------------------',
'  -- On load',
'  ------------------------------------------------',
'  apex_javascript.add_onload_code(',
'      create_object_initial_code(',
'          p_item_name => p_item.name',
'          , p_js_class => l_class',
'          , p_params => l_params',
'      ));',
'',
'end render;',
'',
'procedure ajax(',
'p_item   in            apex_plugin.t_item',
', p_plugin in            apex_plugin.t_plugin',
', p_param  in            apex_plugin.t_item_ajax_param',
', p_result in out nocopy apex_plugin.t_item_ajax_result',
') as',
'l_event             varchar2(4000) := apex_application.g_x01;',
'l_key               varchar2(4000) := apex_application.g_x02;',
'l_type              varchar2(4000) := apex_application.g_x04;',
'l_access_key_id     varchar2(4000) := p_item.attribute_01;',
'l_secret_access_key varchar2(4000) := p_item.attribute_02;',
'l_bucket            varchar2(4000) := p_item.attribute_05;',
'l_expires           number := p_item.attribute_07;',
'l_region            varchar2(4000) := p_item.attribute_08;',
'l_json              clob;',
'begin',
'  ------------------------------------------------',
'  -- Create response',
'  ------------------------------------------------',
'  if l_event = ''upload'' then',
'',
'    l_json := ajax_upload_response(',
'        p_expires_gap => l_expires',
'        , p_bucket => l_bucket',
'        , p_region => l_region',
'        , p_key => l_key',
'        , p_access_key_id => l_access_key_id',
'        , p_secret_access_key => l_secret_access_key',
'        , p_type => l_type',
'    );',
'',
'  elsif l_event = ''delete'' then',
'    l_json := ajax_delete_response(',
'        p_bucket => l_bucket',
'        , p_region => l_region',
'        , p_key => l_key',
'        , p_access_key_id => l_access_key_id',
'        , p_secret_access_key => l_secret_access_key',
'    );',
'  else',
'    raise_application_error(-20000, ''Unsupported event: "'' || l_event || ''"'');',
'  end if;',
'',
'  sys.htp.p(l_json);',
'',
'  exception',
'  when others then',
'  -----------------------------------------',
'  -- Process error',
'  -----------------------------------------',
'  apex_json.open_object;',
'  apex_json.write(''success'', false);',
'  apex_json.write(''code'', SQLCODE);',
'  apex_json.write(''message'', SQLERRM);',
'  apex_json.close_object;',
'end ajax;'))
,p_api_version=>2
,p_render_function=>'render'
,p_ajax_function=>'ajax'
,p_substitute_attributes=>true
,p_subscribe_plugin_settings=>true
,p_version_identifier=>'1.0.0'
,p_files_version=>93
);
wwv_flow_api.create_plugin_attribute(
 p_id=>wwv_flow_api.id(67764690282511309)
,p_plugin_id=>wwv_flow_api.id(67763768571556289)
,p_attribute_scope=>'COMPONENT'
,p_attribute_sequence=>1
,p_display_sequence=>10
,p_prompt=>'Access Key Id'
,p_attribute_type=>'TEXT'
,p_is_required=>true
,p_supported_ui_types=>'DESKTOP:JQM_SMARTPHONE'
,p_supported_component_types=>'APEX_APPLICATION_PAGE_ITEMS'
,p_is_translatable=>false
);
wwv_flow_api.create_plugin_attribute(
 p_id=>wwv_flow_api.id(67765308082503732)
,p_plugin_id=>wwv_flow_api.id(67763768571556289)
,p_attribute_scope=>'COMPONENT'
,p_attribute_sequence=>2
,p_display_sequence=>20
,p_prompt=>'Secret Access Key'
,p_attribute_type=>'TEXT'
,p_is_required=>true
,p_supported_ui_types=>'DESKTOP:JQM_SMARTPHONE'
,p_supported_component_types=>'APEX_APPLICATION_PAGE_ITEMS'
,p_is_translatable=>false
);
wwv_flow_api.create_plugin_attribute(
 p_id=>wwv_flow_api.id(67767078362495392)
,p_plugin_id=>wwv_flow_api.id(67763768571556289)
,p_attribute_scope=>'COMPONENT'
,p_attribute_sequence=>5
,p_display_sequence=>50
,p_prompt=>'Bucket'
,p_attribute_type=>'TEXT'
,p_is_required=>true
,p_supported_ui_types=>'DESKTOP:JQM_SMARTPHONE'
,p_supported_component_types=>'APEX_APPLICATION_PAGE_ITEMS'
,p_is_translatable=>false
);
wwv_flow_api.create_plugin_attribute(
 p_id=>wwv_flow_api.id(67768326446485761)
,p_plugin_id=>wwv_flow_api.id(67763768571556289)
,p_attribute_scope=>'COMPONENT'
,p_attribute_sequence=>7
,p_display_sequence=>70
,p_prompt=>'Expires'
,p_attribute_type=>'INTEGER'
,p_is_required=>true
,p_default_value=>'1800'
,p_supported_ui_types=>'DESKTOP:JQM_SMARTPHONE'
,p_supported_component_types=>'APEX_APPLICATION_PAGE_ITEMS'
,p_is_translatable=>false
);
wwv_flow_api.create_plugin_attribute(
 p_id=>wwv_flow_api.id(27873463710702070)
,p_plugin_id=>wwv_flow_api.id(67763768571556289)
,p_attribute_scope=>'COMPONENT'
,p_attribute_sequence=>8
,p_display_sequence=>80
,p_prompt=>'Region'
,p_attribute_type=>'SELECT LIST'
,p_is_required=>true
,p_default_value=>'eu-west-1'
,p_supported_ui_types=>'DESKTOP:JQM_SMARTPHONE'
,p_supported_component_types=>'APEX_APPLICATION_PAGE_ITEMS'
,p_is_translatable=>false
,p_lov_type=>'STATIC'
);
wwv_flow_api.create_plugin_attr_value(
 p_id=>wwv_flow_api.id(27874476635703652)
,p_plugin_attribute_id=>wwv_flow_api.id(27873463710702070)
,p_display_sequence=>10
,p_display_value=>'US East (N. Virginia)'
,p_return_value=>'us-east-1'
);
wwv_flow_api.create_plugin_attr_value(
 p_id=>wwv_flow_api.id(27874811692704650)
,p_plugin_attribute_id=>wwv_flow_api.id(27873463710702070)
,p_display_sequence=>20
,p_display_value=>'US West (N. California)'
,p_return_value=>'us-west-1'
);
wwv_flow_api.create_plugin_attr_value(
 p_id=>wwv_flow_api.id(27875477194705598)
,p_plugin_attribute_id=>wwv_flow_api.id(27873463710702070)
,p_display_sequence=>30
,p_display_value=>'US West (Oregon)'
,p_return_value=>'us-west-2'
);
wwv_flow_api.create_plugin_attr_value(
 p_id=>wwv_flow_api.id(27875875382706522)
,p_plugin_attribute_id=>wwv_flow_api.id(27873463710702070)
,p_display_sequence=>40
,p_display_value=>'Asia Pacific (Singapore)'
,p_return_value=>'ap-southeast-1'
);
wwv_flow_api.create_plugin_attr_value(
 p_id=>wwv_flow_api.id(27876205763707515)
,p_plugin_attribute_id=>wwv_flow_api.id(27873463710702070)
,p_display_sequence=>50
,p_display_value=>'Asia Pacific (Sydney)'
,p_return_value=>'ap-southeast-2'
);
wwv_flow_api.create_plugin_attr_value(
 p_id=>wwv_flow_api.id(27876661961708594)
,p_plugin_attribute_id=>wwv_flow_api.id(27873463710702070)
,p_display_sequence=>60
,p_display_value=>'Asia Pacific (Tokyo)'
,p_return_value=>'ap-northeast-1'
);
wwv_flow_api.create_plugin_attr_value(
 p_id=>wwv_flow_api.id(27877059559709456)
,p_plugin_attribute_id=>wwv_flow_api.id(27873463710702070)
,p_display_sequence=>70
,p_display_value=>'EU (Ireland)'
,p_return_value=>'eu-west-1'
);
wwv_flow_api.create_plugin_attr_value(
 p_id=>wwv_flow_api.id(27877504969710412)
,p_plugin_attribute_id=>wwv_flow_api.id(27873463710702070)
,p_display_sequence=>80
,p_display_value=>unistr('South America (S\00E3o Paulo)')
,p_return_value=>'sa-east-1'
);
wwv_flow_api.create_plugin_event(
 p_id=>wwv_flow_api.id(80698929336040788)
,p_plugin_id=>wwv_flow_api.id(67763768571556289)
,p_name=>'fmndeleteerror'
,p_display_name=>'Delete Error'
);
wwv_flow_api.create_plugin_event(
 p_id=>wwv_flow_api.id(80699239288040789)
,p_plugin_id=>wwv_flow_api.id(67763768571556289)
,p_name=>'fmndeletesuccess'
,p_display_name=>'Delete Success'
);
end;
/
begin
wwv_flow_api.g_varchar2_table := wwv_flow_api.empty_varchar2_table;
wwv_flow_api.g_varchar2_table(1) := '77696E646F772E46696C654D616E61676572203D2077696E646F772E46696C654D616E61676572207C7C207B7D3B0A2F2A2A0A202A204074797065207B4157533344656C657465526571756573747D0A202A2F0A77696E646F772E46696C654D616E6167';
wwv_flow_api.g_varchar2_table(2) := '65722E4157533344656C65746552657175657374203D202F2A2A2040636C617373202A2F202866756E6374696F6E202829207B0A0A20202F2A2A0A2020202A204074797065207B537472696E677D0A2020202A2040636F6E73740A2020202A2F0A202076';
wwv_flow_api.g_varchar2_table(3) := '61722044454641554C545F4D4554484F44203D202244454C455445223B0A0A20202F2A2A0A2020202A2040636C617373204157533344656C657465526571756573740A2020202A2040696D706C656D656E7473207B53657276657244656C657465526571';
wwv_flow_api.g_varchar2_table(4) := '756573747D0A2020202A2040636F6E7374727563746F720A2020202A0A2020202A2040706172616D207B4157533344656C657465526571756573744F7074696F6E737D206F7074696F6E730A2020202A2F0A202066756E6374696F6E204157533344656C';
wwv_flow_api.g_varchar2_table(5) := '65746552657175657374286F7074696F6E7329207B0A0A202020202F2A2A0A20202020202A20406E616D65204157533344656C6574655265717565737423726571756573740A20202020202A20407479706520584D4C48747470526571756573740A2020';
wwv_flow_api.g_varchar2_table(6) := '2020202A2040726561646F6E6C790A20202020202A2F0A202020204F626A6563742E646566696E6550726F706572747928746869732C202272657175657374222C207B0A20202020202076616C75653A206E657720584D4C487474705265717565737428';
wwv_flow_api.g_varchar2_table(7) := '292C0A2020202020207772697461626C653A2066616C73650A202020207D293B0A0A202020202F2A2A0A20202020202A20406E616D65204157533344656C6574655265717565737423686561646572730A20202020202A20407479706520486561646572';
wwv_flow_api.g_varchar2_table(8) := '5B5D0A20202020202A2040726561646F6E6C790A20202020202A2F0A202020204F626A6563742E646566696E6550726F706572747928746869732C202268656164657273222C207B0A20202020202076616C75653A206F7074696F6E732E686561646572';
wwv_flow_api.g_varchar2_table(9) := '732C0A2020202020207772697461626C653A2066616C73650A202020207D293B0A0A202020202F2A2A0A20202020202A20406E616D65204157533344656C657465526571756573742375726C0A20202020202A20407479706520537472696E670A202020';
wwv_flow_api.g_varchar2_table(10) := '20202A2040726561646F6E6C790A20202020202A2F0A202020204F626A6563742E646566696E6550726F706572747928746869732C202275726C222C207B0A20202020202076616C75653A206F7074696F6E732E75726C2C0A2020202020207772697461';
wwv_flow_api.g_varchar2_table(11) := '626C653A2066616C73650A202020207D293B0A20207D0A0A20202F2A2A0A2020202A20406E616D65204157533344656C657465526571756573742373656E640A2020202A2040706172616D207B53657276657244656C6574655265717565737453656E64';
wwv_flow_api.g_varchar2_table(12) := '4F7074696F6E737D206F7074696F6E730A2020202A2F0A20204157533344656C657465526571756573742E70726F746F747970652E73656E64203D2066756E6374696F6E20286F7074696F6E7329207B0A202020207661722073656C66203D2074686973';
wwv_flow_api.g_varchar2_table(13) := '3B0A0A20202020746869732E726571756573742E6F6E6C6F6164203D2066756E6374696F6E2028657629207B0A2020202020206966202873656C662E726571756573742E737461747573203C20323030207C7C2073656C662E726571756573742E737461';
wwv_flow_api.g_varchar2_table(14) := '747573203E2032393929207B0A20202020202020206F7074696F6E732E6572726F722E63616C6C2873656C662C206E6577204572726F72282243616E6E6F742064656C6574652066696C652C207374617475733A2022202B2073656C662E726571756573';
wwv_flow_api.g_varchar2_table(15) := '742E73746174757329293B0A2020202020207D20656C7365207B0A20202020202020206F7074696F6E732E737563636573732E63616C6C2873656C66293B0A2020202020207D0A202020207D3B0A20202020746869732E726571756573742E6F6E657272';
wwv_flow_api.g_varchar2_table(16) := '6F72203D206F7074696F6E732E6572726F722E62696E642874686973293B0A20202020746869732E726571756573742E75706C6F61642E6F6E6572726F72203D206F7074696F6E732E6572726F722E62696E642874686973293B0A20202020746869732E';
wwv_flow_api.g_varchar2_table(17) := '726571756573742E6F70656E2844454641554C545F4D4554484F442C20746869732E75726C293B0A20202020666F7220287661722069203D20303B2069203C20746869732E686561646572732E6C656E6774683B20692B2B29207B0A2020202020207468';
wwv_flow_api.g_varchar2_table(18) := '69732E726571756573742E7365745265717565737448656164657228746869732E686561646572735B695D2E6865616465722C20746869732E686561646572735B695D2E76616C7565293B0A202020207D0A20202020746869732E726571756573742E73';
wwv_flow_api.g_varchar2_table(19) := '656E6428293B0A20207D3B0A0A202072657475726E204157533344656C657465526571756573743B0A0A7D2928293B0A77696E646F772E46696C654D616E61676572203D2077696E646F772E46696C654D616E61676572207C7C207B7D3B0A2F2A2A0A20';
wwv_flow_api.g_varchar2_table(20) := '2A204074797065207B4157533350726F76696465727D0A202A2F0A77696E646F772E46696C654D616E616765722E4157533350726F7669646572203D202F2A2A2040636C617373202A2F202866756E6374696F6E20286170657829207B0A0A2020696620';
wwv_flow_api.g_varchar2_table(21) := '28216170657829207B0A202020207468726F77206E6577204572726F722822415045582061706920697320756E646566696E65642E22290A20207D0A0A20202F2A2A0A2020202A2040636C617373204157533350726F76696465720A2020202A2040696D';
wwv_flow_api.g_varchar2_table(22) := '706C656D656E7473207B50726F76696465727D0A2020202A2040636F6E7374727563746F720A2020202A0A2020202A2040706172616D207B4157533350726F76696465724F7074696F6E737D206F7074696F6E730A2020202A2F0A202066756E6374696F';
wwv_flow_api.g_varchar2_table(23) := '6E204157533350726F7669646572286F7074696F6E7329207B0A202020202F2A2A0A20202020202A20406E616D65204157533350726F766964657223616A617849640A20202020202A20407479706520537472696E670A20202020202A2040726561646F';
wwv_flow_api.g_varchar2_table(24) := '6E6C790A20202020202A2F0A202020204F626A6563742E646566696E6550726F706572747928746869732C2022616A61784964222C207B0A20202020202076616C75653A206F7074696F6E732E616A617849642C0A2020202020207772697461626C653A';
wwv_flow_api.g_varchar2_table(25) := '2066616C73650A202020207D293B0A20207D0A0A20202F2A2A0A2020202A20406E616D65204157533350726F7669646572236D616B6555706C6F6164526571756573740A2020202A2040706172616D207B5365727665724D616B6555706C6F6164526571';
wwv_flow_api.g_varchar2_table(26) := '756573744F7074696F6E737D206F7074696F6E730A2020202A2F0A20204157533350726F76696465722E70726F746F747970652E6D616B6555706C6F616452657175657374203D2066756E6374696F6E20286F7074696F6E7329207B0A0A202020206966';
wwv_flow_api.g_varchar2_table(27) := '202821746869732E616A6178496429207B0A2020202020206F7074696F6E732E6572726F722E63616C6C28746869732C206E6577204572726F722822416A6178496420697320756E646566696E65642E2229293B0A20202020202072657475726E3B0A20';
wwv_flow_api.g_varchar2_table(28) := '2020207D0A0A20202020617065782E7365727665722E706C7567696E28746869732E616A617849642C207B0A2020202020207830313A202275706C6F6164222C0A2020202020207830323A206F7074696F6E732E66696C652E706174682C0A2020202020';
wwv_flow_api.g_varchar2_table(29) := '207830343A206F7074696F6E732E66696C652E626F64792E747970650A202020207D2C207B0A2020202020202F2A2A0A202020202020202A2040706172616D207B41575333416A617855706C6F61645072657061726174696F6E526573706F6E73657D20';
wwv_flow_api.g_varchar2_table(30) := '646174610A202020202020202A2F0A202020202020737563636573733A2066756E6374696F6E20286461746129207B0A0A20202020202020206966202821646174612E7375636365737329207B0A202020202020202020206F7074696F6E732E6572726F';
wwv_flow_api.g_varchar2_table(31) := '722864617461293B0A2020202020202020202072657475726E3B0A20202020202020207D0A0A20202020202020206F7074696F6E732E73756363657373282F2A2A204074797065207B53657276657255706C6F6164526571756573747D2A2F206E657720';
wwv_flow_api.g_varchar2_table(32) := '77696E646F772E46696C654D616E616765722E4157533355706C6F616452657175657374287B0A2020202020202020202066696C653A206F7074696F6E732E66696C652C0A2020202020202020202075726C3A20646174612E75726C2C0A202020202020';
wwv_flow_api.g_varchar2_table(33) := '20202020646F776E6C6F61643A20646174612E646F776E6C6F61642C0A20202020202020202020686561646572733A20646174612E686561646572730A20202020202020207D29293B0A2020202020207D2C0A0A2020202020206572726F723A2066756E';
wwv_flow_api.g_varchar2_table(34) := '6374696F6E202865727229207B0A20202020202020206F7074696F6E732E6572726F7228657272293B0A2020202020207D0A202020207D293B0A20207D3B0A0A20202F2A2A0A2020202A20406E616D65204157533350726F7669646572236D616B654465';
wwv_flow_api.g_varchar2_table(35) := '6C657465526571756573740A2020202A2040706172616D207B5365727665724D616B6544656C657465526571756573744F7074696F6E737D206F7074696F6E730A2020202A2F0A20204157533350726F76696465722E70726F746F747970652E6D616B65';
wwv_flow_api.g_varchar2_table(36) := '44656C65746552657175657374203D2066756E6374696F6E20286F7074696F6E7329207B0A0A20202020617065782E7365727665722E706C7567696E28746869732E616A617849642C207B0A2020202020207830313A202264656C657465222C0A202020';
wwv_flow_api.g_varchar2_table(37) := '2020207830323A206F7074696F6E732E69640A202020207D2C207B0A2020202020202F2A2A0A202020202020202A2040706172616D207B41575333416A617844656C6574655072657061726174696F6E526573706F6E73657D20646174610A2020202020';
wwv_flow_api.g_varchar2_table(38) := '20202A2F0A202020202020737563636573733A2066756E6374696F6E20286461746129207B0A0A20202020202020206966202821646174612E7375636365737329207B0A202020202020202020206F7074696F6E732E6572726F722864617461293B0A20';
wwv_flow_api.g_varchar2_table(39) := '20202020202020202072657475726E3B0A20202020202020207D0A0A20202020202020206F7074696F6E732E73756363657373282F2A2A204074797065207B53657276657244656C657465526571756573747D2A2F206E65772077696E646F772E46696C';
wwv_flow_api.g_varchar2_table(40) := '654D616E616765722E4157533344656C65746552657175657374287B0A2020202020202020202075726C3A20646174612E75726C2C0A20202020202020202020686561646572733A20646174612E686561646572730A20202020202020207D29293B0A0A';
wwv_flow_api.g_varchar2_table(41) := '2020202020207D2C0A2020202020206572726F723A2066756E6374696F6E202865727229207B0A20202020202020206F7074696F6E732E6572726F7228657272293B0A2020202020207D0A202020207D293B0A20207D3B0A0A20202F2A2A0A2020202A20';
wwv_flow_api.g_varchar2_table(42) := '406E616D65204157533350726F76696465722364656C6574650A2020202A2F0A20204157533350726F76696465722E70726F746F747970652E64656C657465203D2066756E6374696F6E202869642C20737563636573732C206572726F7229207B0A0A20';
wwv_flow_api.g_varchar2_table(43) := '202020766172206576656E7453756363657373203D20646F63756D656E742E6372656174654576656E742822437573746F6D4576656E7422293B0A202020206576656E74537563636573732E696E6974437573746F6D4576656E742822666D6E64656C65';
wwv_flow_api.g_varchar2_table(44) := '746573756363657373222C2066616C73652C2066616C73652C206964293B0A0A20202020766172206576656E744572726F72203D20646F63756D656E742E6372656174654576656E742822437573746F6D4576656E7422293B0A202020206576656E7445';
wwv_flow_api.g_varchar2_table(45) := '72726F722E696E6974437573746F6D4576656E742822666D6E64656C6574656572726F72222C2066616C73652C2066616C73652C206964293B0A0A20202020766172206F7074696F6E73203D207B0A20202020202069643A2069642C0A20202020202073';
wwv_flow_api.g_varchar2_table(46) := '7563636573733A2066756E6374696F6E20282F2A2A204074797065207B53657276657244656C657465526571756573747D2A2F207265717565737429207B0A2020202020202020726571756573742E73656E64287B0A2020202020202020202073756363';
wwv_flow_api.g_varchar2_table(47) := '6573733A2066756E6374696F6E202829207B0A202020202020202020202020696620287375636365737320262620747970656F662073756363657373203D3D3D202266756E6374696F6E2229207B0A202020202020202020202020202073756363657373';
wwv_flow_api.g_varchar2_table(48) := '28293B0A2020202020202020202020207D0A0A202020202020202020202020646F63756D656E742E64697370617463684576656E74286576656E7453756363657373293B0A202020202020202020207D2C0A202020202020202020206572726F723A2066';
wwv_flow_api.g_varchar2_table(49) := '756E6374696F6E202865727229207B0A202020202020202020202020696620286572726F7220262620747970656F66206572726F72203D3D3D202266756E6374696F6E2229207B0A20202020202020202020202020206572726F7228657272293B0A2020';
wwv_flow_api.g_varchar2_table(50) := '202020202020202020207D0A0A202020202020202020202020646F63756D656E742E64697370617463684576656E74286576656E744572726F72293B0A202020202020202020207D0A20202020202020207D293B0A2020202020207D2C0A202020202020';
wwv_flow_api.g_varchar2_table(51) := '6572726F723A2066756E6374696F6E202865727229207B0A2020202020202020696620286572726F7220262620747970656F66206572726F72203D3D3D202266756E6374696F6E2229207B0A202020202020202020206572726F7228657272293B0A2020';
wwv_flow_api.g_varchar2_table(52) := '2020202020207D0A0A2020202020202020646F63756D656E742E64697370617463684576656E74286576656E744572726F72293B0A2020202020207D0A202020207D3B0A0A20202020746869732E6D616B6544656C65746552657175657374286F707469';
wwv_flow_api.g_varchar2_table(53) := '6F6E73293B0A20207D3B0A0A202072657475726E204157533350726F76696465723B0A0A7D292877696E646F772E61706578207C7C20756E646566696E6564293B0A77696E646F772E46696C654D616E61676572203D2077696E646F772E46696C654D61';
wwv_flow_api.g_varchar2_table(54) := '6E61676572207C7C207B7D3B0A2F2A2A0A202A204074797065207B4157533355706C6F6164526571756573747D0A202A2F0A77696E646F772E46696C654D616E616765722E4157533355706C6F616452657175657374203D202F2A2A2040636C61737320';
wwv_flow_api.g_varchar2_table(55) := '2A2F202866756E6374696F6E202829207B0A0A20202F2A2A0A2020202A204074797065207B537472696E677D0A2020202A2040636F6E73740A2020202A2F0A20207661722044454641554C545F4D4554484F44203D2022505554223B0A0A20202F2A2A0A';
wwv_flow_api.g_varchar2_table(56) := '2020202A204074797065207B537472696E677D0A2020202A2040636F6E73740A2020202A202A2F0A2020766172204552524F525F41424F525445445F434F4445203D20225265717565737441626F727465644572726F72223B0A0A20202F2A2A0A202020';
wwv_flow_api.g_varchar2_table(57) := '2A2040636C617373204157533355706C6F6164526571756573740A2020202A2040696D706C656D656E7473207B53657276657255706C6F6164526571756573747D0A2020202A2040636F6E7374727563746F720A2020202A0A2020202A2040706172616D';
wwv_flow_api.g_varchar2_table(58) := '207B4157533355706C6F6164526571756573744F7074696F6E737D206F7074696F6E730A2020202A2F0A202066756E6374696F6E204157533355706C6F616452657175657374286F7074696F6E7329207B0A0A202020202F2A2A0A20202020202A20406E';
wwv_flow_api.g_varchar2_table(59) := '616D65204157533355706C6F61645265717565737423726571756573740A20202020202A20407479706520584D4C48747470526571756573740A20202020202A2040726561646F6E6C790A20202020202A2F0A202020204F626A6563742E646566696E65';
wwv_flow_api.g_varchar2_table(60) := '50726F706572747928746869732C202272657175657374222C207B0A20202020202076616C75653A206E657720584D4C487474705265717565737428292C0A2020202020207772697461626C653A2066616C73650A202020207D293B0A0A202020202F2A';
wwv_flow_api.g_varchar2_table(61) := '2A0A20202020202A20406E616D65204157533355706C6F6164526571756573742375726C0A20202020202A20407479706520537472696E670A20202020202A2040726561646F6E6C790A20202020202A2F0A202020204F626A6563742E646566696E6550';
wwv_flow_api.g_varchar2_table(62) := '726F706572747928746869732C202275726C222C207B0A20202020202076616C75653A206F7074696F6E732E75726C2C0A2020202020207772697461626C653A2066616C73650A202020207D293B0A0A202020202F2A2A0A20202020202A20406E616D65';
wwv_flow_api.g_varchar2_table(63) := '204157533355706C6F61645265717565737423646F776E6C6F61640A20202020202A20407479706520537472696E670A20202020202A2040726561646F6E6C790A20202020202A2F0A202020204F626A6563742E646566696E6550726F70657274792874';
wwv_flow_api.g_varchar2_table(64) := '6869732C2022646F776E6C6F6164222C207B0A20202020202076616C75653A206F7074696F6E732E646F776E6C6F61642C0A2020202020207772697461626C653A2066616C73650A202020207D293B0A0A202020202F2A2A0A20202020202A20406E616D';
wwv_flow_api.g_varchar2_table(65) := '65204157533355706C6F6164526571756573742366696C650A20202020202A2040747970652046696C65536F757263650A20202020202A2040726561646F6E6C790A20202020202A2F0A202020204F626A6563742E646566696E6550726F706572747928';
wwv_flow_api.g_varchar2_table(66) := '746869732C202266696C65222C207B0A20202020202076616C75653A206F7074696F6E732E66696C652C0A2020202020207772697461626C653A2066616C73650A202020207D293B0A0A202020202F2A2A0A20202020202A20406E616D65204157533355';
wwv_flow_api.g_varchar2_table(67) := '706C6F61645265717565737423686561646572730A20202020202A204074797065204865616465725B5D0A20202020202A2040726561646F6E6C790A20202020202A2F0A202020204F626A6563742E646566696E6550726F706572747928746869732C20';
wwv_flow_api.g_varchar2_table(68) := '2268656164657273222C207B0A20202020202076616C75653A206F7074696F6E732E686561646572732C0A2020202020207772697461626C653A2066616C73650A202020207D293B0A20207D0A0A20202F2A2A0A2020202A20406E616D65204157533355';
wwv_flow_api.g_varchar2_table(69) := '706C6F6164526571756573742373656E640A2020202A2040706172616D207B53657276657255706C6F61645265717565737453656E644F7074696F6E737D206F7074696F6E730A2020202A2F0A20204157533355706C6F6164526571756573742E70726F';
wwv_flow_api.g_varchar2_table(70) := '746F747970652E73656E64203D2066756E6374696F6E20286F7074696F6E7329207B0A0A202020207661722073656C66203D20746869733B0A0A20202020746869732E726571756573742E6F6E6C6F6164203D2066756E6374696F6E2028657629207B0A';
wwv_flow_api.g_varchar2_table(71) := '2020202020206966202873656C662E726571756573742E73746174757320213D3D2032303029207B0A20202020202020206F7074696F6E732E6572726F722E63616C6C2873656C662C206E6577204572726F72282243616E6E6F742075706C6F61642066';
wwv_flow_api.g_varchar2_table(72) := '696C652C207374617475733A2022202B2073656C662E726571756573742E73746174757329293B0A2020202020207D20656C7365207B0A20202020202020206F7074696F6E732E737563636573732E63616C6C2873656C662C202F2A2A20407479706520';
wwv_flow_api.g_varchar2_table(73) := '53657276657255706C6F6164526573706F6E7365202A2F207B0A2020202020202020202069643A2073656C662E66696C652E706174682C0A202020202020202020206E616D653A2073656C662E66696C652E6E616D652C0A202020202020202020207572';
wwv_flow_api.g_varchar2_table(74) := '6C3A2073656C662E646F776E6C6F61642C0A202020202020202020206F726967696E616C3A2073656C662E66696C652E626F64792E6E616D652C0A20202020202020202020747970653A2073656C662E66696C652E626F64792E747970652C0A20202020';
wwv_flow_api.g_varchar2_table(75) := '20202020202073697A653A2073656C662E66696C652E626F64792E73697A650A20202020202020207D293B0A2020202020207D0A202020207D3B0A20202020746869732E726571756573742E75706C6F61642E6F6E70726F6772657373203D206F707469';
wwv_flow_api.g_varchar2_table(76) := '6F6E732E70726F67726573732E62696E642874686973293B0A20202020746869732E726571756573742E75706C6F61642E6F6E61626F7274203D206F7074696F6E732E61626F72742E62696E642874686973293B0A20202020746869732E726571756573';
wwv_flow_api.g_varchar2_table(77) := '742E6F6E6572726F72203D206F7074696F6E732E6572726F722E62696E642874686973293B0A20202020746869732E726571756573742E75706C6F61642E6F6E6572726F72203D206F7074696F6E732E6572726F722E62696E642874686973293B0A2020';
wwv_flow_api.g_varchar2_table(78) := '2020746869732E726571756573742E6F70656E2844454641554C545F4D4554484F442C20746869732E75726C293B0A20202020666F7220287661722069203D20303B2069203C20746869732E686561646572732E6C656E6774683B20692B2B29207B0A20';
wwv_flow_api.g_varchar2_table(79) := '2020202020746869732E726571756573742E7365745265717565737448656164657228746869732E686561646572735B695D2E6865616465722C20746869732E686561646572735B695D2E76616C7565293B0A202020207D0A20202020746869732E7265';
wwv_flow_api.g_varchar2_table(80) := '71756573742E73656E6428746869732E66696C652E626F6479293B0A20207D3B0A0A20202F2A2A0A2020202A20406E616D65204157533355706C6F6164526571756573742361626F72740A2020202A2F0A20204157533355706C6F616452657175657374';
wwv_flow_api.g_varchar2_table(81) := '2E70726F746F747970652E61626F7274203D2066756E6374696F6E202829207B0A20202020746869732E726571756573742E61626F727428293B0A20207D3B0A0A202072657475726E204157533355706C6F6164526571756573743B0A0A7D2928293B';
null;
end;
/
begin
wwv_flow_api.create_plugin_file(
 p_id=>wwv_flow_api.id(67764089104553660)
,p_plugin_id=>wwv_flow_api.id(67763768571556289)
,p_file_name=>'aws3-provider.js'
,p_mime_type=>'application/javascript'
,p_file_charset=>'utf-8'
,p_file_content=>wwv_flow_api.varchar2_to_blob(wwv_flow_api.g_varchar2_table)
);
end;
/
begin
wwv_flow_api.g_varchar2_table := wwv_flow_api.empty_varchar2_table;
wwv_flow_api.g_varchar2_table(1) := '77696E646F772E46696C654D616E616765723D77696E646F772E46696C654D616E616765727C7C7B7D2C77696E646F772E46696C654D616E616765722E4157533344656C657465526571756573743D66756E6374696F6E28297B66756E6374696F6E2065';
wwv_flow_api.g_varchar2_table(2) := '2865297B4F626A6563742E646566696E6550726F706572747928746869732C2272657175657374222C7B76616C75653A6E657720584D4C48747470526571756573742C7772697461626C653A21317D292C4F626A6563742E646566696E6550726F706572';
wwv_flow_api.g_varchar2_table(3) := '747928746869732C2268656164657273222C7B76616C75653A652E686561646572732C7772697461626C653A21317D292C4F626A6563742E646566696E6550726F706572747928746869732C2275726C222C7B76616C75653A652E75726C2C7772697461';
wwv_flow_api.g_varchar2_table(4) := '626C653A21317D297D72657475726E20652E70726F746F747970652E73656E643D66756E6374696F6E2865297B76617220743D746869733B746869732E726571756573742E6F6E6C6F61643D66756E6374696F6E2872297B742E726571756573742E7374';
wwv_flow_api.g_varchar2_table(5) := '617475733C3230307C7C742E726571756573742E7374617475733E3239393F652E6572726F722E63616C6C28742C6E6577204572726F72282243616E6E6F742064656C6574652066696C652C207374617475733A20222B742E726571756573742E737461';
wwv_flow_api.g_varchar2_table(6) := '74757329293A652E737563636573732E63616C6C2874297D2C746869732E726571756573742E6F6E6572726F723D652E6572726F722E62696E642874686973292C746869732E726571756573742E75706C6F61642E6F6E6572726F723D652E6572726F72';
wwv_flow_api.g_varchar2_table(7) := '2E62696E642874686973292C746869732E726571756573742E6F70656E282244454C455445222C746869732E75726C293B666F722876617220723D303B723C746869732E686561646572732E6C656E6774683B722B2B29746869732E726571756573742E';
wwv_flow_api.g_varchar2_table(8) := '7365745265717565737448656164657228746869732E686561646572735B725D2E6865616465722C746869732E686561646572735B725D2E76616C7565293B746869732E726571756573742E73656E6428297D2C657D28292C77696E646F772E46696C65';
wwv_flow_api.g_varchar2_table(9) := '4D616E616765723D77696E646F772E46696C654D616E616765727C7C7B7D2C77696E646F772E46696C654D616E616765722E4157533350726F76696465723D66756E6374696F6E2865297B6966282165297468726F77206E6577204572726F7228224150';
wwv_flow_api.g_varchar2_table(10) := '45582061706920697320756E646566696E65642E22293B66756E6374696F6E20742865297B4F626A6563742E646566696E6550726F706572747928746869732C22616A61784964222C7B76616C75653A652E616A617849642C7772697461626C653A2131';
wwv_flow_api.g_varchar2_table(11) := '7D297D72657475726E20742E70726F746F747970652E6D616B6555706C6F6164526571756573743D66756E6374696F6E2874297B746869732E616A617849643F652E7365727665722E706C7567696E28746869732E616A617849642C7B7830313A227570';
wwv_flow_api.g_varchar2_table(12) := '6C6F6164222C7830323A742E66696C652E706174682C7830343A742E66696C652E626F64792E747970657D2C7B737563636573733A66756E6374696F6E2865297B652E737563636573733F742E73756363657373286E65772077696E646F772E46696C65';
wwv_flow_api.g_varchar2_table(13) := '4D616E616765722E4157533355706C6F616452657175657374287B66696C653A742E66696C652C75726C3A652E75726C2C646F776E6C6F61643A652E646F776E6C6F61642C686561646572733A652E686561646572737D29293A742E6572726F72286529';
wwv_flow_api.g_varchar2_table(14) := '7D2C6572726F723A66756E6374696F6E2865297B742E6572726F722865297D7D293A742E6572726F722E63616C6C28746869732C6E6577204572726F722822416A6178496420697320756E646566696E65642E2229297D2C742E70726F746F747970652E';
wwv_flow_api.g_varchar2_table(15) := '6D616B6544656C657465526571756573743D66756E6374696F6E2874297B652E7365727665722E706C7567696E28746869732E616A617849642C7B7830313A2264656C657465222C7830323A742E69647D2C7B737563636573733A66756E6374696F6E28';
wwv_flow_api.g_varchar2_table(16) := '65297B652E737563636573733F742E73756363657373286E65772077696E646F772E46696C654D616E616765722E4157533344656C65746552657175657374287B75726C3A652E75726C2C686561646572733A652E686561646572737D29293A742E6572';
wwv_flow_api.g_varchar2_table(17) := '726F722865297D2C6572726F723A66756E6374696F6E2865297B742E6572726F722865297D7D297D2C742E70726F746F747970652E64656C6574653D66756E6374696F6E28652C742C72297B76617220733D646F63756D656E742E637265617465457665';
wwv_flow_api.g_varchar2_table(18) := '6E742822437573746F6D4576656E7422293B732E696E6974437573746F6D4576656E742822666D6E64656C65746573756363657373222C21312C21312C65293B76617220693D646F63756D656E742E6372656174654576656E742822437573746F6D4576';
wwv_flow_api.g_varchar2_table(19) := '656E7422293B692E696E6974437573746F6D4576656E742822666D6E64656C6574656572726F72222C21312C21312C65293B766172206E3D7B69643A652C737563636573733A66756E6374696F6E2865297B652E73656E64287B737563636573733A6675';
wwv_flow_api.g_varchar2_table(20) := '6E6374696F6E28297B7426262266756E6374696F6E223D3D747970656F66207426267428292C646F63756D656E742E64697370617463684576656E742873297D2C6572726F723A66756E6374696F6E2865297B7226262266756E6374696F6E223D3D7479';
wwv_flow_api.g_varchar2_table(21) := '70656F6620722626722865292C646F63756D656E742E64697370617463684576656E742869297D7D297D2C6572726F723A66756E6374696F6E2865297B7226262266756E6374696F6E223D3D747970656F6620722626722865292C646F63756D656E742E';
wwv_flow_api.g_varchar2_table(22) := '64697370617463684576656E742869297D7D3B746869732E6D616B6544656C65746552657175657374286E297D2C747D2877696E646F772E617065787C7C766F69642030292C77696E646F772E46696C654D616E616765723D77696E646F772E46696C65';
wwv_flow_api.g_varchar2_table(23) := '4D616E616765727C7C7B7D2C77696E646F772E46696C654D616E616765722E4157533355706C6F6164526571756573743D66756E6374696F6E28297B66756E6374696F6E20652865297B4F626A6563742E646566696E6550726F70657274792874686973';
wwv_flow_api.g_varchar2_table(24) := '2C2272657175657374222C7B76616C75653A6E657720584D4C48747470526571756573742C7772697461626C653A21317D292C4F626A6563742E646566696E6550726F706572747928746869732C2275726C222C7B76616C75653A652E75726C2C777269';
wwv_flow_api.g_varchar2_table(25) := '7461626C653A21317D292C4F626A6563742E646566696E6550726F706572747928746869732C22646F776E6C6F6164222C7B76616C75653A652E646F776E6C6F61642C7772697461626C653A21317D292C4F626A6563742E646566696E6550726F706572';
wwv_flow_api.g_varchar2_table(26) := '747928746869732C2266696C65222C7B76616C75653A652E66696C652C7772697461626C653A21317D292C4F626A6563742E646566696E6550726F706572747928746869732C2268656164657273222C7B76616C75653A652E686561646572732C777269';
wwv_flow_api.g_varchar2_table(27) := '7461626C653A21317D297D72657475726E20652E70726F746F747970652E73656E643D66756E6374696F6E2865297B76617220743D746869733B746869732E726571756573742E6F6E6C6F61643D66756E6374696F6E2872297B323030213D3D742E7265';
wwv_flow_api.g_varchar2_table(28) := '71756573742E7374617475733F652E6572726F722E63616C6C28742C6E6577204572726F72282243616E6E6F742075706C6F61642066696C652C207374617475733A20222B742E726571756573742E73746174757329293A652E737563636573732E6361';
wwv_flow_api.g_varchar2_table(29) := '6C6C28742C7B69643A742E66696C652E706174682C6E616D653A742E66696C652E6E616D652C75726C3A742E646F776E6C6F61642C6F726967696E616C3A742E66696C652E626F64792E6E616D652C747970653A742E66696C652E626F64792E74797065';
wwv_flow_api.g_varchar2_table(30) := '2C73697A653A742E66696C652E626F64792E73697A657D297D2C746869732E726571756573742E75706C6F61642E6F6E70726F67726573733D652E70726F67726573732E62696E642874686973292C746869732E726571756573742E75706C6F61642E6F';
wwv_flow_api.g_varchar2_table(31) := '6E61626F72743D652E61626F72742E62696E642874686973292C746869732E726571756573742E6F6E6572726F723D652E6572726F722E62696E642874686973292C746869732E726571756573742E75706C6F61642E6F6E6572726F723D652E6572726F';
wwv_flow_api.g_varchar2_table(32) := '722E62696E642874686973292C746869732E726571756573742E6F70656E2822505554222C746869732E75726C293B666F722876617220723D303B723C746869732E686561646572732E6C656E6774683B722B2B29746869732E726571756573742E7365';
wwv_flow_api.g_varchar2_table(33) := '745265717565737448656164657228746869732E686561646572735B725D2E6865616465722C746869732E686561646572735B725D2E76616C7565293B746869732E726571756573742E73656E6428746869732E66696C652E626F6479297D2C652E7072';
wwv_flow_api.g_varchar2_table(34) := '6F746F747970652E61626F72743D66756E6374696F6E28297B746869732E726571756573742E61626F727428297D2C657D28293B';
null;
end;
/
begin
wwv_flow_api.create_plugin_file(
 p_id=>wwv_flow_api.id(68531959117989805)
,p_plugin_id=>wwv_flow_api.id(67763768571556289)
,p_file_name=>'aws3-provider.min.js'
,p_mime_type=>'application/javascript'
,p_file_charset=>'utf-8'
,p_file_content=>wwv_flow_api.varchar2_to_blob(wwv_flow_api.g_varchar2_table)
);
end;
/
begin
wwv_flow_api.import_end(p_auto_install_sup_obj => nvl(wwv_flow_application_install.get_auto_install_sup_obj, false), p_is_component_import => true);
commit;
end;
/
set verify on feedback on define on
prompt  ...done
