<?php

/* List the known types and modes */
$GLOBALS['known'] = array(
	'assoc_types'	=> array('HMAC-SHA1'),

	'openid_modes'	=> array('accept',
				 'associate',
				 'authorize_site',
				 'checkid_immediate',
				 'checkid_setup',
				 'check_authentication',
				 'error',
				 ),

	'session_types'	=> array('',
				 'DH-SHA1'),

	'bigmath_types' => array('DH-SHA1'),
);

/* $g Defined by OpenID spec */
$GLOBALS['g'] = 2;

/* $p Defined by OpenID spec */
$GLOBALS['p'] = '155172898181473697471232257763715539915724801966915404479707' .
'7953140576293785419175806512274236981889937278161526466314385615958256881888' .
'8995127215884267541995034125870655654980358010487053768147672651325574704076' .
'5857479291291572334510643245094715007229621094194349783925984760375594985848' .
'253359305585439638443';

/* Default lifetime of an association */
$GLOBALS['assoc_life'] = 1440;

/* Include what we need */
require_once('openid_constants.php');
require_once('util.php');

/*****************************************************************************
 * Runmode functions *
*****************************************************************************/

/* Perform an association with a consumer */
function associate_mode()
{
	global $p, $g, $known, $assoc_life;

	// Validate the request
	if (!isset($_REQUEST['openid_mode']) || $_REQUEST['openid_mode'] != 'associate')
		error(400);

	// Get the request options, using defaults as necessary
	$assoc_type = (@strlen($_REQUEST['openid_assoc_type'])
		    && in_array($_REQUEST['openid_assoc_type'], $known['assoc_types']))
			? $_REQUEST['openid_assoc_type']
			: 'HMAC-SHA1';

	$session_type = (@strlen($_REQUEST['openid_session_type'])
		      && in_array($_REQUEST['openid_session_type'], 
					$known['session_types']))
			? $_REQUEST['openid_session_type']
			: '';

	$dh_modulus = (@strlen($_REQUEST['openid_dh_modulus']))
		? long(base64_decode($_REQUEST['openid_dh_modulus']))
		: ($session_type == 'DH-SHA1'
			? $p
			: null);

	$dh_gen = (@strlen($_REQUEST['openid_dh_gen']))
		? long(base64_decode($_REQUEST['openid_dh_gen']))
		: ($session_type == 'DH-SHA1'
			? $g
			: null);

	$dh_consumer_public = (@strlen($_REQUEST['openid_dh_consumer_public']))
		? $_REQUEST['openid_dh_consumer_public']
		: ($session_type == 'DH-SHA1'
			? error_post('dh_consumer_public was not specified')
			: null);

	$lifetime = time() + $assoc_life;

	// Create standard keys
	$keys = array(
		'assoc_type' => $assoc_type,
		'expires_in' => $assoc_life
	);

	// If I can't handle bigmath, default to plaintext sessions
	if (in_array($session_type, $known['bigmath_types']))
		$session_type = null;

	// Add response keys based on the session type
	switch ($session_type) {
		case 'DH-SHA1':
			// Create the associate id and shared secret now
			list ($assoc_handle, $shared_secret) = new_assoc($lifetime);

			// Compute the Diffie-Hellman stuff
			$private_key = random($dh_modulus);
			$public_key = bmpowmod($dh_gen, $private_key, $dh_modulus);
			$remote_key = long(base64_decode($dh_consumer_public));
			$ss = bmpowmod($remote_key, $private_key, $dh_modulus);

			$keys['assoc_handle'] = $assoc_handle;
			$keys['session_type'] = $session_type;
			$keys['dh_server_public'] = base64_encode(bin($public_key));
			$keys['enc_mac_key'] = base64_encode(x_or(sha1_20(bin($ss)), $shared_secret));
			break;

		default:
			// Create the associate id and shared secret now
			list ($assoc_handle, $shared_secret) = new_assoc($lifetime);
			$keys['assoc_handle'] = $assoc_handle;
			$keys['mac_key'] = base64_encode($shared_secret);
	}

	// Return the keys
	wrap_kv($keys);
}

/* Handle a consumer's request to see if the user is authenticated */
function check_authentication_mode()
{
	// Validate the request
	if (!isset($_REQUEST['openid_mode']) ||
		$_REQUEST['openid_mode'] != 'check_authentication')
		error(400);

	$assoc_handle = @strlen($_REQUEST['openid_assoc_handle'])
		? $_REQUEST['openid_assoc_handle']
		: error_post('Missing assoc_handle');

	$sig = @strlen($_REQUEST['openid_sig'])
		? $_REQUEST['openid_sig']
		: error_post('Missing sig');

	$signed = @strlen($_REQUEST['openid_signed'])
		? $_REQUEST['openid_signed']
		: error_post('Missing signed');
	
	// extract identity
	if (isset($_REQUEST['openid_identity'])) {
		$identity = $_REQUEST['openid_identity'];
	} else if (isset($_REQUEST['openid_claimed_id'])) {
		$identity = $_REQUEST['openid_claimed_id'];
	} else {
		error_post('Missing identity');
	}

	// extract site
	$site = array_key_exists('openid_return_to', $_REQUEST) 
					? $_REQUEST['openid_return_to']
					: "";
					
	if (!strlen($site)) {
		$site = array_key_exists('openid_realm', $_REQUEST) 
						? $_REQUEST['openid_realm']
						: error_post('Missing return_to/realm');
	}
						
	// Prepare the return keys
	$keys = array(
		'openid.mode' => 'id_res'
	);

	// Invalidate the assoc handle if we need to
	if (@strlen($_REQUEST['openid_invalidate_handle'])) {
		destroy_assoc($_REQUEST['openid_invalidate_handle']);
		$keys['invalidate_handle'] = $_REQUEST['openid_invalidate_handle'];
	}

	// Validate the sig by recreating the kv pair and signing
	$_REQUEST['openid_mode'] = 'id_res';
	$tokens = '';
	foreach (explode(',', $signed) as $param) {
		$post = preg_replace('/\./', '_', $param);
		$tokens .= sprintf("%s:%s\n", $param, $_REQUEST['openid_' . $post]);
	}

	/* Add the sreg stuff, if we've got it
	if (isset($sreg_required)) {
		foreach (explode(',', $sreg_required) as $key) {
			if (! isset($sreg[$key]))
				continue;
			$skey = 'sreg.' . $key;

			$tokens .= sprintf("%s:%s\n", $skey, $sreg[$key]);
			$keys[$skey] = $sreg[$key];
			$fields[] = $skey;
		}
	}
	*/
	
	// Look up the consumer's shared_secret and timeout
	list($shared_secret, $expires) = secret($assoc_handle);

	// if I can't verify the assoc_handle, or if it's expired
	if ($shared_secret == false ||
		(is_numeric($expires) && $expires < time())) {
		$keys['is_valid'] = 'false';
	} else {
		$ok = base64_encode(hmac($shared_secret, $tokens));
		$keys['is_valid'] = ($sig == $ok) ? 'true' : 'false';
	}

	// Return the keys
	wrap_kv($keys);
}

/* Create a new site authorization. This is not a real OpenID mode, the client 
 * makes this request on behalf of the user */
function authorize_site_mode()
{
	global $assoc_life;
	
	// Get the options, use defaults as necessary
	$return_to = @strlen($_REQUEST['openid_return_to'])
		? $_REQUEST['openid_return_to']
		: error_400('Missing return_to');

	$identity = @strlen($_REQUEST['openid_identity'])
			? $_REQUEST['openid_identity']
			: error_get($return_to, 'Missing identity');

	$assoc_handle = @strlen($_REQUEST['openid_assoc_handle'])
			? $_REQUEST['openid_assoc_handle']
			: null;

	$trust_root = @strlen($_REQUEST['openid_trust_root'])
			? $_REQUEST['openid_trust_root']
			: $return_to;

	$sreg_required = @strlen($_REQUEST['openid_sreg_required'])
			? $_REQUEST['openid_sreg_required']
			: '';

	$sreg_optional = @strlen($_REQUEST['openid_sreg_optional'])
			? $_REQUEST['openid_sreg_optional']
			: '';

	// determine the cancel url
	$q = strpos($return_to, '?') ? '&' : '?';
	$cancel_url = $return_to . $q . 'openid.mode=cancel';

	// required and optional make no difference to us
	$sreg_required .= ',' . $sreg_optional;
	
	// do the trust_root analysis
	if ($trust_root != $return_to) {
		// the urls are not the same, be sure return decends from trust
		if (!url_descends($return_to, $trust_root))
			error_500('Invalid trust_root');
	}

	// check the assoc handle
	list($shared_secret, $expires) = secret($assoc_handle);

	// if I can't verify the assoc_handle, or if it's expired
	if ($shared_secret == false ||
		(is_numeric($expires) && $expires < time())) {
		debug("Session expired or missing key: $expires < " . time());
		if ($assoc_handle != null) {
			$keys['invalidate_handle'] = $assoc_handle;
			destroy_assoc($assoc_handle);
		}

		$lifetime = time() + $assoc_life;
		list($assoc_handle, $shared_secret) = new_assoc($lifetime);
	}
	
	if (check_weave_login($identity, $_REQUEST['weave_pwd'])) {
		$keys['mode'] = 'id_res';
		$keys['identity'] =  OPENID_SERVER_NAME . $identity;
		$keys['assoc_handle'] = $assoc_handle;
		$keys['return_to'] = $return_to;
	} else {
		debug("Cannot validate weave id: $identity");
		error(401, $cancel_url);
	}
	
	$fields = array_keys($keys);
	$tokens = '';
	foreach ($fields as $key)
		$tokens .= sprintf("%s:%s\n", $key, $keys[$key]);
	
	/* add sreg keys
	foreach (explode(',', $sreg_required) as $key) {
		if (! isset($sreg[$key]))
			continue;
		$skey = 'sreg.' . $key;

		$tokens .= sprintf("%s:%s\n", $skey, $sreg[$key]);
		$keys[$skey] = $sreg[$key];
		$fields[] = $skey;
	} */
	
	$keys['signed'] = implode(',', $fields);
	$keys['sig'] = base64_encode(hmac($shared_secret, $tokens));
	
	/* Ok, send final URL to client */
	$keys = append_openid($keys);
	$q = strpos($return_to, '?') ? '&' : '?';
	debug("Sending " . $return_to . $q . http_build_query($keys));
	echo $return_to . $q . http_build_query($keys);
}

/* We don't support checkid_immediate and always ask for checkid_setup so that   
 * the client can intercept the redirect */
function checkid_immediate_mode()
{
	if (!isset($_REQUEST['openid_mode']) ||
		$_REQUEST['openid_mode'] != 'checkid_immediate')
		error(500);
	$keys['mode'] = 'setup_needed';
	wrap_kv($keys);
}


/* We should never get the checkid_setup request, it should have been 
 * intercepted by the client and authorize_site_mode should be called */
function checkid_setup_mode()
{
	if (!isset($_REQUEST['openid_mode']) ||
		$_REQUEST['openid_mode'] != 'checkid_setup')
		error(500);
	echo "Whoops, looks like you tried to login with your Weave ID without Firefox and the addon!";
}

/* Handle errors */
function error_mode()
{
	error(500, $_REQUEST['openid_error']);
}

/* Display user endpoint */
function user_page($user)
{
	header('Content-Type: text/html');
?>
 <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
	<head>
		<title>OpenID User Page</title>
		<link rel="openid.server" href="https://services.mozilla.com/openid/" />
		<meta name="robots" content="noindex,nofollow" />
	</head>
	<body>
		<p>You are looking at the OpenID endpoint for user <?= $user ?></p>
	</body>
</html>
<?php
}

/*****************************************************************************
 * Association, key support and authorization functions *
*****************************************************************************/

/* Check the validity of a weave login */
function check_weave_login($user, $password)
{
	if (defined('WEAVE_AUTH_URL'))
		$cluster = file_get_contents(WEAVE_AUTH_URL . $user . '/node/weave/');
	else
		$cluster = WEAVE_STORAGE_URL;
	$req = $cluster . '1.0/' . $user . '/storage/keys/pubkey';

	$ses = curl_init($req);
	curl_setopt($ses, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ses, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($ses, CURLOPT_USERPWD, $user . ":" . $password);
	$ret = curl_exec($ses);
	$hed = curl_getinfo($ses);
	curl_close($ses);

	return $hed['http_code'] == 200 ? true : false;
}

/* Create a new consumer association */
function new_assoc($expiration)
{
	$id = sha1(mt_rand().mt_rand());
	$shared_secret = new_secret();
	debug('Started new assoc session: ' . $id);

	try {
		$dbh = new PDO('mysql:host=' . OPENID_MYSQL_HOST . ';dbname=' .
			OPENID_MYSQL_DB, OPENID_MYSQL_USER, OPENID_MYSQL_PASS);
		$sth = $dbh->prepare("INSERT into openid VALUES
			(:id, :secret, :expire)");
		$sth->bindParam(':id', $id);
		$sth->bindParam(':secret', $shared_secret);
		$sth->bindParam(':expire', $expiration);
		$sth->execute();
	} catch(PDOException $exception) {
		debug("new_assoc: " . $exception->getMessage());
	}

	return array($id, $shared_secret);
}

/* Destroy a consumer's assoc handle */
function destroy_assoc($handle)
{
	try {
		$dbh = new PDO('mysql:host=' . OPENID_MYSQL_HOST . ';dbname=' .
			OPENID_MYSQL_DB, OPENID_MYSQL_USER, OPENID_MYSQL_PASS);
		$sth = $dbh->prepare("DELETE FROM openid WHERE id = :handle");
		$sth->bindParam(':handle', $handle);
		debug("Destroying session $handle: " . $sth->execute());
	} catch(PDOException $exception) {
		debug("destroy_assoc: " . $exception->getMessage());
	}
}

/* Create a new shared secret */
function new_secret()
{
	$r = '';
	for($i=0; $i<20; $i++)
		$r .= chr(mt_rand(0, 255));

	debug("Generated new key: hash = '" . md5($r) .
		"', length = '" . strlen($r) . "'");
	return $r;
}

/* Get the shared secret and expiration time for the specified assoc_handle */
function secret($handle)
{
	if (!preg_match('/^\w+$/', $handle))
		return array(false, 0);
	
	$row = false;
	try {
		$dbh = new PDO('mysql:host=' . OPENID_MYSQL_HOST . ';dbname=' .
			OPENID_MYSQL_DB, OPENID_MYSQL_USER, OPENID_MYSQL_PASS);
		$sth = $dbh->prepare("SELECT * FROM openid WHERE id = :handle");
		$sth->bindParam(':handle', $handle);
		$sth->execute();
		$row = $sth->fetch(PDO::FETCH_ASSOC);
	} catch(PDOException $exception) {
		debug("find_secret: " . $exception->getMessage());
	}
	
	return array($row['secret'], (int)($row['expire']));
}

/* Let's get started! */

// Set the internal encoding
if (function_exists('mb_internal_encoding'))
	mb_internal_encoding('iso-8859-1');

// Avoid problems with non-default arg_separator.output settings
// Credit for this goes to user 'prelog' on the forums
ini_set('arg_separator.output', '&');

/* Determine the HTTP request port */
$GLOBALS['port'] = ((isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] == 'on' && $_SERVER['SERVER_PORT'] == 443)
	  || $_SERVER['SERVER_PORT'] == 80)
		? ''
		: ':' . $_SERVER['SERVER_PORT'];

/* Determine the HTTP request protocol */
$GLOBALS['proto'] = (isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] == 'on') ? 'https' : 'http';

/* Maybe this is a user page */

// note: user is set as a GET param via mod_rewrite
if (isset($_REQUEST['user'])) {
	$user = $_REQUEST['user'];
	if (!get_magic_quotes_gpc())
		$user = addslashes($user);
		user_page(htmlspecialchars($user));
		exit(0);
}

/* Decide which runmode and run it! */
$run_mode = (isset($_REQUEST['openid_mode'])
	  && in_array($_REQUEST['openid_mode'], $known['openid_modes']))
	? $_REQUEST['openid_mode']
	: 'no';
debug("Run mode: $run_mode at: " . time());
debug($_REQUEST, 'Request params');
call_user_func($run_mode . '_mode');

?>
