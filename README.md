[![No Maintenance Intended](http://unmaintained.tech/badge.svg)](http://unmaintained.tech/)

# [SMF](http://www.simplemachines.org/) LDAP Plugin

Small plugin I wrote to authenticate LDAP users with SMF forum. I never bothered to package this to SMF pugin format. This project is not maintained in any way.

## Installation

Copy files to Sources directory overwriting existing files, modify database (ldap_user column to _members table) and add hooks by executing ldap_install.php. Also try not to break anything in progress. Then add: define('LDAP_BASE_DN', 'ou=xyz,dc=example,dc=com'); to Settings.php.

## License

http://www.simplemachines.org/about/smf/license.php BSD
