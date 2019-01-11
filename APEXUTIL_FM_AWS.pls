create or replace package apexutil_fm_aws as

  function get_url(
      p_key               in varchar2
    , p_bucket            in varchar2
    , p_region            in varchar2
    , p_expires           in number
    , p_access_key_id     in varchar2
    , p_secret_access_key in varchar2
  )
    return varchar2;

end apexutil_fm_aws;