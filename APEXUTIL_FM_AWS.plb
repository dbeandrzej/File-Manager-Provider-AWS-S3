create or replace package body apexutil_fm_aws as

  g_timestamp_format constant varchar2(21) := 'yyyy-mm-dd hh24:mi:ss';
  g_utf8_encoding_code constant varchar2(8) := 'AL32UTF8';

  g_amazon_url constant varchar2(13) := 'amazonaws.com';
  g_s3 constant varchar2(2) := 's3';

  g_us_east_n_virginia constant varchar2(9) := 'us-east-1'; --Versions 2 and 4
  g_us_west_n_california constant varchar2(9) := 'us-west-1'; --Versions 2 and 4
  g_us_west_oregon constant varchar2(9) := 'us-west-2'; --Versions 2 and 4
  g_asia_pacific_singapore constant varchar2(14) := 'ap-southeast-1'; --Versions 2 and 4
  g_asia_pacific_sydney constant varchar2(14) := 'ap-southeast-2'; --Versions 2 and 4
  g_asia_pacific_tokyo constant varchar2(14) := 'ap-northeast-1'; --Versions 2 and 4
  g_eu_ireland constant varchar2(9) := 'eu-west-1'; --Versions 2 and 4
  g_south_america_sao_paulo constant varchar2(9) := 'sa-east-1'; --Versions 2 and 4

  function is_signature_v2(
    p_region in varchar2
  )
    return boolean as
    begin
      return p_region = g_us_east_n_virginia
             or p_region = g_us_west_n_california
             or p_region = g_us_west_oregon
             or p_region = g_asia_pacific_singapore
             or p_region = g_asia_pacific_sydney
             or p_region = g_asia_pacific_tokyo
             or p_region = g_eu_ireland
             or p_region = g_south_america_sao_paulo;
    end is_signature_v2;

  /**
   *
   */
  function get_canonicalized(
      p_bucket in varchar2
    , p_key    in varchar2
  )
    return varchar2
  as
    begin
      return utl_url.escape('/' || p_bucket || '/' || p_key);
    end get_canonicalized;

  /**
   *
   */
  function get_context(
      p_region        in varchar2
    , p_canonicalized in varchar2
  )
    return varchar2 as
    begin
      if is_signature_v2(p_region) then
        return '//' || g_s3 || '.' || p_region || '.' || g_amazon_url || p_canonicalized;
      else
        raise_application_error(-20000, 'Unsupported region.');
      end if;
    end get_context;

  /**
   *
   */
  function get_utc_unix_time
    return number
  as
    begin
      return trunc((to_date(to_char(sys_extract_utc(systimestamp), g_timestamp_format), g_timestamp_format) -
                    to_date('19700101', 'YYYYMMDD')) * 86400);
    end get_utc_unix_time;

  /**
   *
   */
  function get_string_to_sign(
      p_expires       in number
    , p_canonicalized in varchar2
  )
    return varchar2 as
    begin
      return 'GET' || chr(10) || chr(10) || chr(10) || p_expires || chr(10) || p_canonicalized;
    end get_string_to_sign;

  /**
   *
   */
  function sign_string(
      p_string_to_sign    in varchar2
    , p_secret_access_key in varchar2
  )
    return varchar2 as
    l_string_to_sign_utf8_raw    raw(1000);
    l_secret_access_key_utf8_raw raw(1000);
    l_encrypted_sgnt_raw         raw(1000);
    l_encrypted_sgnt_base64_raw  raw(1000);
    begin
      l_string_to_sign_utf8_raw := utl_i18n.string_to_raw(p_string_to_sign, g_utf8_encoding_code);
      l_secret_access_key_utf8_raw := utl_i18n.string_to_raw(p_secret_access_key, g_utf8_encoding_code);

      l_encrypted_sgnt_raw := dbms_crypto.mac(l_string_to_sign_utf8_raw, dbms_crypto.HMAC_SH1,
                                              l_secret_access_key_utf8_raw);
      l_encrypted_sgnt_base64_raw := utl_encode.base64_encode(l_encrypted_sgnt_raw);

      return utl_i18n.raw_to_char(l_encrypted_sgnt_base64_raw, g_utf8_encoding_code);
    end sign_string;

  /**
   *
   */
  function get_auth(
      p_access_key_id in varchar2
    , p_signature     in varchar2
    , p_expires       in number
  )
    return varchar2 as
    begin
      return '?AWSAccessKeyId=' || p_access_key_id || '&Signature=' || wwv_flow_utilities.url_encode2(p_signature) ||
             '&Expires=' || p_expires;
    end get_auth;

  /**
   *
   */
  function get_url(
      p_key               in varchar2
    , p_bucket            in varchar2
    , p_region            in varchar2
    , p_expires           in number
    , p_access_key_id     in varchar2
    , p_secret_access_key in varchar2
  )
    return varchar2 as

    l_canonicalized varchar2(4000);
    l_context       varchar2(4000);
    l_expires       number;
    l_sting_to_sign varchar2(4000);
    l_signature     varchar2(4000);
    l_auth          varchar2(4000);

    begin

      l_canonicalized := get_canonicalized(p_bucket, p_key);
      l_context := get_context(p_region, l_canonicalized);
      l_expires := get_utc_unix_time() + p_expires;
      l_sting_to_sign := get_string_to_sign(l_expires, l_canonicalized);
      l_signature := sign_string(l_sting_to_sign, p_secret_access_key);
      l_auth := get_auth(p_access_key_id, l_signature, l_expires);

      return l_context || l_auth;
    end get_url;

end apexutil_fm_aws;