<?php

require_once('math.php');

/* Generic error display */
function error($code, $message = null) {
	switch ($code) {
		case 400: header("HTTP/1.1 400 Bad Request"); break;
		case 403: header("HTTP/1.1 403 Forbidden"); break;
		case 500: header("HTTP/1.1 500 Internal Server Error"); break;
	}
	
	echo $message;
	exit(0);
}

/* Return an error message to the consumer */
function error_get ( $url, $message = 'Bad Request') {
	wrap_keyed_redirect($url, array('mode' => 'error', 'error' => $message));
}

/* Return an error message to the consumer */
function error_post($message = 'Bad Request') {
	header("HTTP/1.1 400 Bad Request");
	echo ('error:' . $message);
	exit(0);
}

/* Create http_build_query if missing */
if (!function_exists('http_build_query')) {
	function http_build_query($array) {
		$r = array();
		foreach ($array as $key => $val)
			$r[] = sprintf('%s=%s', urlencode($key), urlencode($val));
		return implode('&', $r);
	}
}

/* Prefix the keys of an array with  'openid.' */
function append_openid($array) {
	$keys = array_keys($array);
	$vals = array_values($array);

	$r = array();
	for ($i=0; $i<sizeof($keys); $i++)
		$r['openid.' . $keys[$i]] = $vals[$i];
	return $r;
}

/* Return a key-value pair in plain text */
function wrap_kv($keys) {
	debug($keys, 'Wrapped key/vals');
	header('Content-Type: text/plain; charset=iso-8859-1');
	foreach ($keys as $key => $value)
		printf("%s:%s\n", $key, $value);
	exit(0);
}

/* Redirect, with OpenID keys */
function wrap_keyed_redirect($url, $keys) {
	$keys = append_openid($keys);
	debug($keys, 'Location keys');

	$q = strpos($url, '?') ? '&' : '?';
	wrap_redirect($url . $q . http_build_query($keys));
}

/* Redirect the browser */
function wrap_redirect($url) {
	header('HTTP/1.1 302 Found');
	header('Location: ' . $url);
	debug('Location: ' . $url);
	exit(0);
}

/* Implement binary x_or */
function x_or($a, $b) {
	$r = "";

	for ($i = 0; $i < strlen($b); $i++)
		$r .= $a[$i] ^ $b[$i];
	debug("Xor size: " . strlen($r));
	return $r;
}

/* Random number generation */
function random($max) {
	if (strlen($max) < 4)
		return mt_rand(1, $max - 1);

	$r = '';
	for($i=1; $i<strlen($max) - 1; $i++)
		$r .= mt_rand(0,9);
	$r .= mt_rand(1,9);

	return $r;
}

/* Do an HMAC */
function hmac($key, $data, $hash = 'sha1_20') {
	$blocksize=64;

	if (strlen($key) > $blocksize)
		$key = $hash($key);

	$key = str_pad($key, $blocksize,chr(0x00));
	$ipad = str_repeat(chr(0x36),$blocksize);
	$opad = str_repeat(chr(0x5c),$blocksize);

	$h1 = $hash(($key ^ $ipad) . $data);
	$hmac = $hash(($key ^ $opad) . $h1);
	return $hmac;
}

/* Do SHA1 20 byte encryption */
function sha1_20($v) {
	if (version_compare(phpversion(), '5.0.0', 'ge'))
		return sha1($v, true);

	$hex = sha1($v);
	$r = '';
	for ($i = 0; $i < 40; $i += 2) {
		$hexcode = substr($hex, $i, 2);
		$charcode = base_convert($hexcode, 16, 10);
		$r .= chr($charcode);
	}
	return $r;
}

/* Get a binary value. From http://openidenabled.com */
function bin($n) {
	$bytes = array();
	while (bmcomp($n, 0) > 0) {
		array_unshift($bytes, bmmod($n, 256));
		$n = bmdiv($n, bmpow(2,8));
	}

	if ($bytes && ($bytes[0] > 127))
		array_unshift($bytes, 0);

	$b = '';
	foreach ($bytes as $byte)
		$b .= pack('C', $byte);

	return $b;
}

/* Turn a binary back into a long. Also from http://openidenabled.com */
function long($b) {
	$bytes = array_merge(unpack('C*', $b));
	$n = 0;
	foreach ($bytes as $byte) {
		$n = bmmul($n, bmpow(2,8));
		$n = bmadd($n, $byte);
	}
	return $n;
}

/* Look for the point of differentiation in two strings */
function str_diff_at($a, $b) {
	if ($a == $b)
		return -1;
	$n = min(strlen($a), strlen($b));
	for ($i = 0; $i < $n; $i++)
		if ($a[$i] != $b[$i])
			return $i;
	return $n;
}

/* Debug logging */
function debug($x, $m = null) {
	$logfile = '/var/log/openid_log';
	if (!is_writable(dirname($logfile)) &! is_writable($logfile))
		error(500, 'Cannot write to debug log: ' . $logfile);

	if (is_array($x)) {
		ob_start();
		print_r($x);
		$x = $m . ($m != null ? "\n" : '') . ob_get_clean();

	} else {
		$x .= "\n";
	}

	error_log($x . "\n", 3, $logfile);
}

/* Determine if a child URL actually decends from the parent, and that the
 * parent is a good URL. */
function url_descends($child, $parent) {
	if ($child == $parent)
		return true;

	$keys = array();
	$parts = array();

	$req = array('scheme', 'host');
	$bad = array('fragment', 'pass', 'user');

	foreach (array('parent', 'child') as $name) {
		$parts[$name] = @parse_url($$name);
		if ($parts[$name] === false)
			return false;

		$keys[$name] = array_keys($parts[$name]);

		if (array_intersect($keys[$name], $req) != $req)
			return false;

		if (array_intersect($keys[$name], $bad) != array())
			return false;

		if (! preg_match('/^https?$/i', strtolower($parts[$name]['scheme'])))
			return false;

		if (! array_key_exists('port', $parts[$name]))
			$parts[$name]['port'] = (strtolower($parts[$name]['scheme']) == 'https') ? 443 : 80;

		if (! array_key_exists('path', $parts[$name]))
			$parts[$name]['path'] = '/';
	}

	// port and scheme must match
	if ($parts['parent']['scheme'] != $parts['child']['scheme'] ||
	    $parts['parent']['port'] != $parts['child']['port'])
		return false;

	// compare the hosts by reversing the strings
	$cr_host = strtolower(strrev($parts['child']['host']));
	$pr_host = strtolower(strrev($parts['parent']['host']));

	$break = str_diff_at($cr_host, $pr_host);
	if ($break >= 0 && ($pr_host[$break] != '*' || substr_count(substr($pr_host, 0, $break), '.') < 2))
		return false;

	// now compare the paths
	$break = str_diff_at($parts['child']['path'], $parts['parent']['path']);
	if ($break >= 0
	   && ($break < strlen($parts['parent']['path']) && $parts['parent']['path'][$break] != '*')
	   || ($break > strlen($parts['child']['path'])))
		return false;

	return true;
}

?>