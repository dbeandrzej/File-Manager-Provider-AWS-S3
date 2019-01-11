# File Manager Provider AWS S3 (Oracle APEX Plugin)
File Manager Provider AWS S3 plugin provides connection between the File Manager Component plugin and Amazon S3 cloud. It is a member of the family of plugins for file management in your APEX application.
For more details see [File Manager Component](https://github.com/dbeandrzej/File-Manager-Component).

## PL/SQL API
### APEXUTIL_FM_AWS
* get_url

#### get_url
Generates download url for the file which is specified by the key (more details Amazon Query String Request Authentication).
```sql
function get_url(
    p_key               in varchar2
  , p_bucket            in varchar2
  , p_region            in varchar2
  , p_expires           in number
  , p_access_key_id     in varchar2
  , p_secret_access_key in varchar2
) return varchar2;
```
###### Parameters
* p_key - file identifier;
* p_bucket - bucket name;
* p_region - region of the amazon endpoint (Signature Version 2);
* p_expires - life time of the url in milliseconds;
* p_access_key_id - amazon access key identifier;
* p_secret_access_key - amazon secret access key.

## Links
* [File Manager Component](https://github.com/dbeandrzej/File-Manager-Component)
* [How to install](#)
* [Download File Manager Сomponent plugin](https://apexfilesdir.s3.eu-west-1.amazonaws.com/apexutil/public_files/item_type_plugin_com_apexutil_fm_component.sql)
* [Download File Manager Provider AWS-S3 plugin](https://apexfilesdir.s3.eu-west-1.amazonaws.com/apexutil/public_files/item_type_plugin_com_apexutil_fm_provider_aws3.sql)
* [Download PL/SQL API](https://apexfilesdir.s3.eu-west-1.amazonaws.com/apexutil/public_files/apexutil_fm_aws.zip)
* [APEXUTIL.COM](https://www.apexutil.com)
* [Demo](https://www.apexutil.com/apex/f?p=700:200)