<?php

/**
 * Simple Machines Forum (SMF) Ldap Plugin
 *
 * @package SMF-LDAP
 * @author hyrskynmyrsky@gmail.com
 *
 * @version 1.0
 */

if (!defined('SMF'))
	die('Hacking attempt...');

/**
 * function ldap_escape
 * @author Chris Wright
 * @version 2.0
 * @param string $subject The subject string
 * @param bool $dn Treat subject as a DN if TRUE
 * @param string|array $ignore Set of characters to leave untouched
 * @return string The escaped string
 */
function ldap_escape ($subject, $dn = FALSE, $ignore = NULL) {

    // The base array of characters to escape
    // Flip to keys for easy use of unset()
    $search = array_flip($dn ? array('\\', ',', '=', '+', '<', '>', ';', '"', '#') : array('\\', '*', '(', ')', "\x00"));

    // Process characters to ignore
    if (is_array($ignore)) {
        $ignore = array_values($ignore);
    }
    for ($char = 0; isset($ignore[$char]); $char++) {
        unset($search[$ignore[$char]]);
    }

    // Flip $search back to values and build $replace array
    $search = array_keys($search); 
    $replace = array();
    foreach ($search as $char) {
        $replace[] = sprintf('\\%02x', ord($char));
    }

    // Do the main replacement
    $result = str_replace($search, $replace, $subject);

    // Encode leading/trailing spaces in DN values
    if ($dn) {
        if ($result[0] == ' ') {
            $result = '\\20'.substr($result, 1);
        }
        if ($result[strlen($result) - 1] == ' ') {
            $result = substr($result, 0, -1).'\\20';
        }
    }

    return $result;
}


function ldapHashPassword($password, $salt)
{
	$packed = pack("H*", sha1($password.$salt));
	$encoded = base64_encode($packed.$salt);
	return "{SSHA}".$encoded;
}

function ldap_register(&$regOptions, $theme_vars)
{
	if ($regOptions['auth_method'] != 'ldap') {
	    // FIXME: Ugly hack:
	    // Create regular user if something fails on the way or create unusable account?
	    $regOptions['auth_method'] = 'ldap';
	    $regOptions['register_vars']['ldap_user'] = 1;

	    if (!function_exists('ldap_connect')) {
	    	return;
	   	} 

		$ldap = ldap_connect(LDAP_SERVER, LDAP_PORT);

		if (!is_resource($ldap)) {
	        return;
	    }

	    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
	    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

	    if (!ldap_bind($ldap, LDAP_ADMIN, LDAP_ADMIN_PW))
	    	return;

		$entry["objectClass"][0] = "top";
		$entry["objectClass"][1] = "simpleSecurityObject";
		$entry["objectClass"][2] = "account";
		$entry["objectClass"][3] = "extensibleObject";
		$entry["userpassword"] = ldapHashPassword($regOptions['password'], 
			openssl_random_pseudo_bytes(16));

		$entry["mail"] = $regOptions['email'];
		$entry["cn"] = $regOptions['register_vars']['real_name'];

	    // add data to directory
	    ldap_add($ldap, 'uid='.ldap_escape($regOptions['username']).','.LDAP_BASE_DN, $entry) or die("LDAP Add failed");
	}
}

function ldap_verify_password($username, $password)
{
	global $user_info;

	if (!(bool)ord($user_info['ldap_user']))
		return; // Do nothing

    if (!function_exists('ldap_connect')) {
    	return;
   	} 

	$ldap = ldap_connect(LDAP_SERVER, LDAP_PORT);

	if (!is_resource($ldap)) {
        return;
    }

    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

    // return true on success
    return ldap_bind($ldap, 'uid='.ldap_escape($username).','.LDAP_BASE_DN, $password);
}

function ldap_reset_pass($old_user, $user, $newPassword)
{
	global $user_profile;

	$result = loadMemberData($user, true);
	if(!is_array($result))
		die("Failed to load member data");

	if (!(bool)ord($user_profile[$result[0]]['ldap_user']))
		return; // Do nothing

    if (!function_exists('ldap_connect')) {
    	return;
   	} 

	$ldap = ldap_connect(LDAP_SERVER, LDAP_PORT);

	if (!is_resource($ldap)) {
        return;
    }

    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

    if (!ldap_bind($ldap, LDAP_ADMIN, LDAP_ADMIN_PW))
    	return;

    $entry['userpassword'] = ldapHashPassword($newPassword, 
    	openssl_random_pseudo_bytes(16));

    ldap_modify($ldap, 'uid='.ldap_escape($user).','.LDAP_BASE_DN, $entry) or die('LDAP Modify failed');
}

function ldap_change_member_data($member_names, $var, $data)
{
	global $user_profile;

	$result = loadMemberData($member_names, true);
	if(!is_array($result))
		die("Failed to load member data");

	// Remove each non-ldap user from array
	foreach ($result as $i => $id) {
		if (!(integer)$user_profile[$id]['ldap_user'])
			unset($member_names[$i]);
	}

/*
	// Not optimal test: Should iterate every member in 
	// $member_names and check if they are ldap users
	if ($user_info['ldap_user'] == false)
		return; // Do nothing
*/

	$entry = array();

	switch ($var) {
		case 'member_name':
			$entry['uid'] = $data;
			break;
		case 'real_name':
			$entry['cn'] = $data;
			break;
		case 'email_address':
			$entry['mail'] = $data;
			break;
		default:
			return;
	}

    if (!empty($entry) && !empty($member_names)) {
	    if (!function_exists('ldap_connect')) {
	    	return;
	   	} 

		$ldap = ldap_connect(LDAP_SERVER, LDAP_PORT);

		if (!is_resource($ldap)) {
	        return;
	    }

	    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
	    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

	    if (!ldap_bind($ldap, LDAP_ADMIN, LDAP_ADMIN_PW)) 
	    	return;

	    foreach ($member_names as $member) {
		    @ldap_modify($ldap, 'uid='.ldap_escape($member).','.LDAP_BASE_DN, $entry) or die("LDAP Modify failed");
		}
	}
}

function ldap_delete_member($memberId) 
{
	global $user_profile;

	if(!loadMemberData($memberId))
		die("Failed to load member data");

	if ($user_profile[$memberId]['ldap_user']) {
	    if (!function_exists('ldap_connect')) {
	    	return;
	   	} 

		$ldap = ldap_connect(LDAP_SERVER, LDAP_PORT);

		if (!is_resource($ldap)) {
	        return;
	    }

	    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
	    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

	    if (!ldap_bind($ldap, LDAP_ADMIN, LDAP_ADMIN_PW)) 
	    	return;

		ldap_delete($ldap, 'uid='.$user_profile[$memberId]['member_name'].','.LDAP_BASE_DN ) or die("LDAP Delete failed");
	}
}

?>
