<?php

// If SSI.php is in the same place as this file, and SMF isn't defined, this is being run standalone.
if (file_exists(dirname(__FILE__) . '/SSI.php') && !defined('SMF'))
	require_once(dirname(__FILE__) . '/SSI.php');
// Hmm... no SSI.php and no SMF?
elseif (!defined('SMF'))
	die('<b>Error:</b> Cannot install - please verify you put this in the same place as SMF\'s index.php.');

add_integration_function('integrate_pre_include', '$sourcedir/Subs-Ldap.php');
add_integration_function('integrate_register', 'ldap_register');
add_integration_function('integrate_verify_password', 'ldap_verify_password');
add_integration_function('integrate_reset_pass', 'ldap_reset_pass');
add_integration_function('integrate_change_member_data', 'ldap_change_member_data');
add_integration_function('integrate_delete_member', 'ldap_delete_member');

echo "Done!"

// + modify database

?>
