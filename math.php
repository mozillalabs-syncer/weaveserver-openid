<?php
# ***** BEGIN LICENSE BLOCK *****
# Version: GPL 2.0
#
# The contents of this file are subject to the terms of the GNU General Public 
# License Version 2 (the "GPL") you may not use this file except in compliance 
# with the License. You may obtain a copy of the License at
# http://www.gnu.org/licenses/gpl.html
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is phpMyId (http://siege.org/projects/phpMyID/).
#
# The Initial Developer of the Original Code is:
#   CJ Niemira (siege@siege.org)
#
# Portions created by the Initial Developer are Copyright (C) 2008
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Anant Narayanan (anant@mozilla.com)
#
# ***** END LICENSE BLOCK *****

/* For all the math functions: bcadd -> gmp -> fallback */

/* big math addition function */
function bmadd($l, $r) {
	if (function_exists('bcadd'))
		return bcadd($l, $r);

	if (function_exists('gmp_add') && function_exists('gmp_strval'))
		return gmp_strval(gmp_add($l, $r));

	$l = strval($l); $r = strval($r);
	$ll = strlen($l); $rl = strlen($r);
	if ($ll < $rl) {
		$l = str_repeat("0", $rl-$ll) . $l;
		$o = $rl;

	} elseif ( $ll > $rl ) {
		$r = str_repeat("0", $ll-$rl) . $r;
		$o = $ll;

	} else {
		$o = $ll;
	}

	$v = '';
	$carry = 0;

	for ($i = $o-1; $i >= 0; $i--) {
		$d = (int)$l[$i] + (int)$r[$i] + $carry;
		if ($d <= 9) {
			$carry = 0;

		} else {
			$carry = 1;
			$d -= 10;
		}
		$v = (string) $d . $v;
	}

	if ($carry > 0)
		$v = "1" . $v;

	return $v;
}

/* big math comparison function */
function bmcomp($l, $r) {
	if (function_exists('bccomp'))
		return bccomp($l, $r);
	
	if (function_exists('gmp_cmp') && function_exists('gmp_strval'))
		return gmp_strval(gmp_cmp($l, $r));

	$l = strval($l); $r = strval($r);
	$ll = strlen($l); $lr = strlen($r);
	if ($ll != $lr)
		return ($ll > $lr) ? 1 : -1;

	return strcmp($l, $r);
}

/* big math division function */
function bmdiv($l, $r, $z = 0) {
	if (function_exists('bcdiv'))
		return ($z == 0) ? bcdiv($l, $r) : bcmod($l, $r);

	if (function_exists('gmp_div_q') && function_exists('gmp_strval'))
		return gmp_strval(($z == 0) ? gmp_div_q($l, $r) : gmp_mod($l, $r));

	$l = strval($l); $r = strval($r);
	$v = '0';

	while (true) {
		if( bmcomp($l, $r) < 0 )
			break;

		$delta = strlen($l) - strlen($r);
		if ($delta >= 1) {
			$zeroes = str_repeat("0", $delta);
			$r2 = $r . $zeroes;

			if (strcmp($l, $r2) >= 0) {
				$v = bmadd($v, "1" . $zeroes);
				$l = bmsub($l, $r2);

			} else {
				$zeroes = str_repeat("0", $delta - 1);
				$v = bmadd($v, "1" . $zeroes);
				$l = bmsub($l, $r . $zeroes);
			}

		} else {
			$l = bmsub($l, $r);
			$v = bmadd($v, "1");
		}
	}

	return ($z == 0) ? $v : $l;
}

/* Create a big math multiplication function */
function bmmul($l, $r) {
	if (function_exists('bcmul'))
		return bcmul($l, $r);

	if (function_exists('gmp_mul') && function_exists('gmp_strval'))
		return gmp_strval(gmp_mul($l, $r));

	$l = strval($l); $r = strval($r);

	$v = '0';
	$z = '';

	for( $i = strlen($r)-1; $i >= 0; $i-- ){
		$bd = (int) $r[$i];
		$carry = 0;
		$p = "";
		for( $j = strlen($l)-1; $j >= 0; $j-- ){
			$ad = (int) $l[$j];
			$pd = $ad * $bd + $carry;
			if( $pd <= 9 ){
				$carry = 0;
			} else {
				$carry = (int) ($pd / 10);
				$pd = $pd % 10;
			}
			$p = (string) $pd . $p;
		}
		if( $carry > 0 )
			$p = (string) $carry . $p;
		$p = $p . $z;
		$z .= "0";
		$v = bmadd($v, $p);
	}

	return $v;
}

/* big math modulus function */
function bmmod($value, $mod) {
	if (function_exists('bcmod'))
		return bcmod($value, $mod);

	if (function_exists('gmp_mod') && function_exists('gmp_strval'))
		return gmp_strval(gmp_mod($value, $mod));

	$r = bmdiv($value, $mod, 1);
	return $r;
}

/* big math power function */
function bmpow($value, $exponent) {
	if (function_exists('bcpow'))
		return bcpow($value, $exponent);

	if (function_exists('gmp_pow') && function_exists('gmp_strval'))
		return gmp_strval(gmp_pow($value, $exponent));

	$r = '1';
	while ($exponent) {
		$r = bmmul($r, $value, 100);
		$exponent--;
	}
	return (string)rtrim($r, '0.');
}

/* big math 'powmod' function */
function bmpowmod ($value, $exponent, $mod) {
	if (function_exists('bcpowmod'))
		return bcpowmod($value, $exponent, $mod);

	if (function_exists('gmp_powm') && function_exists('gmp_strval'))
		return gmp_strval(gmp_powm($value, $exponent, $mod));

	$r = '';
	while ($exponent != '0') {
		$t = bmmod($exponent, '4096');
		$r = substr("000000000000" . decbin(intval($t)), -12) . $r;
		$exponent = bmdiv($exponent, '4096');
	}

	$r = preg_replace("!^0+!","",$r);

	if ($r == '')
		$r = '0';
	$value = bmmod($value, $mod);
	$erb = strrev($r);
	$q = '1';
	$a[0] = $value;

	for ($i = 1; $i < strlen($erb); $i++) {
		$a[$i] = bmmod( bmmul($a[$i-1], $a[$i-1]), $mod );
	}

	for ($i = 0; $i < strlen($erb); $i++) {
		if ($erb[$i] == "1") {
			$q = bmmod( bmmul($q, $a[$i]), $mod );
		}
	}

	return($q);
}

/* big math subtraction function */
function bmsub($l, $r) {
	if (function_exists('bcsub'))
		return bcsub($l, $r);

	if (function_exists('gmp_sub') && function_exists('gmp_strval'))
		return gmp_strval(gmp_sub($l, $r));


	$l = strval($l); $r = strval($r);
	$ll = strlen($l); $rl = strlen($r);

	if ($ll < $rl) {
		$l = str_repeat("0", $rl-$ll) . $l;
		$o = $rl;
	} elseif ( $ll > $rl ) {
		$r = str_repeat("0", $ll-$rl) . (string)$r;
		$o = $ll;
	} else {
		$o = $ll;
	}

	if (strcmp($l, $r) >= 0) {
		$sign = '';
	} else {
		$x = $l; $l = $r; $r = $x;
		$sign = '-';
	}

	$v = '';
	$carry = 0;

	for ($i = $o-1; $i >= 0; $i--) {
		$d = ($l[$i] - $r[$i]) - $carry;
		if ($d < 0) {
			$carry = 1;
			$d += 10;
		} else {
			$carry = 0;
		}
		$v = (string) $d . $v;
	}

	return $sign . ltrim($v, '0');
}

?>