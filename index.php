<?php
# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is Weave Openid Server
#
# The Initial Developer of the Original Code is
# Mozilla Labs.
# Portions created by the Initial Developer are Copyright (C) 2008
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#	Anant Narayanan (anant@mozilla.com)
#	Dan Mills (thunder@mozilla.com)
#	Toby Elliott (telliott@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****

	include 'openid_constants.php';
	
	function do_log($msg)
	{
		$logfile = fopen(OPEND_DEBUG_LOG, 'a');
		fwrite($logfile, $msg."\n\n");
		fclose($logfile);
	}

	function report_problem($message, $code = 503)
	{
		$headers = array('400' => '400 Bad Request',
					'401' => '401 Unauthorized',
					'404' => '404 Not Found',
					'500' => '500 Internal Server Error',
					'503' => '503 Service Unavailable');
		header('HTTP/1.1 ' . $headers{$code},true,$code);
				
		exit('Error: ' . $message . '(' . $code . ')');
	}

	function getSignature($id, $token, $site, $root, $user) 
	{
		$kv  = "mode:id_res\n";
		$kv .= "identity:$id\n";
		$kv .= "assoc_handle:$token\n";
		$kv .= "return_to:$site\n";
		$kv .= "sreg.nickname:$user\n";
		
		if ($root) 
			$kv .= "trust_root:$root\n";
		
		return base64_encode(hash_hmac('sha1', $kv, $token, true));
	}
	
	function check_weave_login($user, $password)
	{
		if (defined('WEAVE_AUTH_CLUSTER_URL'))
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
	
	function add_authorization($user, $site, $token) 
	{
		try
		{
			$dbh = new PDO('mysql:host=' . OPENID_MYSQL_HOST . ';dbname=' . OPENID_MYSQL_DB, OPENID_MYSQL_USER, OPENID_MYSQL_PASS);
			$sth = $dbh->prepare("REPLACE into openid VALUES (:username, :site, :token, NOW())");
			$sth->bindParam(':username', $user);
			$sth->bindParam(':site', $site);
			$sth->bindParam(':token', $token);
			$sth->execute();
			return;
		}
		catch( PDOException $exception )
		{
			error_log("add_authorization: " . $exception->getMessage());
			report_problem("$site&openid.mode=cancel", 500);
		}		
	}

	function check_authentication($user, $site, $token) 
	{
		try
		{
			$dbh = new PDO('mysql:host=' . OPENID_MYSQL_HOST . ';dbname=' . OPENID_MYSQL_DB, OPENID_MYSQL_USER, OPENID_MYSQL_PASS);
			$sth = $dbh->prepare("SELECT 1 FROM openid WHERE username = :username and site = :site and token = :token");
			$sth->bindParam(':username', $user);
			$sth->bindParam(':site', $site);
			$sth->bindParam(':token', $token);
			$sth->execute();
			return $sth->fetch();
		}
		catch( PDOException $exception )
		{
			error_log("check_authentication: " . $exception->getMessage());
			report_problem("Database Unavailable", 500);
		}		
	}

	function user_page($user) 
	{
		header('Content-Type: text/html');
?>
		<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
		<html>
			<head>
				<title>OpenID User Page</title>
				<link rel="openid.server" href="<?= OPENID_SERVER_NAME ?>" />
				<meta name="robots" content="noindex,nofollow" />
			</head>
			<body>
				<p>You are looking at the OpenID endpoint for user <?= $user ?></p>
			</body>
		</html>
<?php
	}

        // Log incoming requests for debugging
        do_log(var_export($_REQUEST, true));

	// Mode switcher
	// note: user is set as a GET param via mod_rewrite
	
	if (array_key_exists('user', $_REQUEST))
	{
		$user = $_REQUEST['user'];
		if (!get_magic_quotes_gpc())
			$user = addslashes($user);
		user_page(htmlspecialchars($user));
		exit;
	}
	
	if (!array_key_exists('openid_mode', $_REQUEST))
		report_problem('Missing openid_mode', 400);
	
	switch (strtolower($_REQUEST['openid_mode'])) 
	{
		case 'associate':
			report_problem('Stateful authentication not supported', 400);
			break;
		case 'authorize_site':
			$identity = array_key_exists('openid_identity', $_REQUEST) 
							? substr($_REQUEST['openid_identity'], strlen(OPENID_SERVER_NAME)) # removing the servername
							: report_problem('Missing identity URL', 400);
			$password = array_key_exists('weave_pwd', $_POST)  ? $_POST['weave_pwd'] : report_problem('Missing weave pwd', 400);
			$site = array_key_exists('openid_return_to', $_POST)  ? $_POST['openid_return_to'] : report_problem('Missing return_to', 400);
			$root = array_key_exists('openid_trust_root', $_POST)  ? $_POST['openid_trust_root'] : false;

			$token = sha1(mt_rand().$identity.$site);
			$insu = $root ? $root : $site;

			if (check_weave_login($identity, $password))
			{
				add_authorization($identity, $insu, $token);
			}
			else
			{
				report_problem ($site . "&openid.mode=cancel", 401);
			}
			$id = OPENID_SERVER_NAME . "$user";
			$signed = "mode,identity,assoc_handle,return_to,sreg.nickname";
	
			if ($root)
				$signed .= ",trust_root";
	 
			$final  = $site;
			$final .= strpos($site, '?') ? '&' : '?'; #technically, this would be bad if character 1 is a ?, but that's bogus input
			$final .= 'openid.mode=id_res';
			$final .= '&openid.identity=' . urlencode(OPENID_SERVER_NAME . $identity);
			$final .= '&openid.assoc_handle=' . $token;
			$final .= '&openid.return_to=' . urlencode($site);
			$final .= '&openid.sreg.nickname=' . urlencode($identity);
			if ($root)
			    $final .= '&openid.trust_root=' . urlencode($root);
			$final .= '&openid.signed=' . urlencode($signed);
			$final .= '&openid.sig=' . getSignature($id, $token, $site, $root, $user);
		
			echo $final;
			break;
		case 'check_authentication':
			$identity = array_key_exists('openid_identity', $_REQUEST) 
							? substr($_REQUEST['openid_identity'], strlen(OPENID_SERVER_NAME)) # removing the server name
							: report_problem('Missing identity URL', 400);
							
			$site = array_key_exists('openid_trust_root', $_REQUEST) 
							? $_REQUEST['openid_trust_root']
							: "";
							
			if (!strlen($site))
				$site = array_key_exists('openid_return_to', $_REQUEST) 
								? $_REQUEST['openid_return_to']
								: report_problem('Missing return_to / trust_root', 400);

			$token = array_key_exists('openid_assoc_handle', $_REQUEST) 
							? $_REQUEST['openid_assoc_handle']
							: report_problem('Missing assoc_handle token', 400);
							
			header('Content-Type: text/plain');
			$keys = array('openid_mode' => "id_res", 
						  'is_valid' => check_authentication($identity, $site, $token) ? "true" : "false");
			foreach ($keys as $key => $value)
				printf("%s:%s\n", $key, $value);

			break;
		default:
		  report_problem('Mode ' . $_REQUEST['openid_mode'] . ' not supported', 400);
	}

?>

