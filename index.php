<?php

define('DATAFILE', __DIR__.'/.data.json');
define('MAXDATA', 10485760);
define('LIVE_UPDATE', 300);
define('MIN_REFRESH', 30);

$FILE = NULL;
$DATA = NULL;
$FILEMTIME=0;
$FILESIZE=0;
$FILEHASH="";
$VERBOSITY=0;

$NOW = time();

##### UNIVERSAL FUNCTIONS #####

function openData($retries = 5) {
	global $FILE,$FILEMTIME,$FILESIZE,$FILEHASH,$DATA,$NOW;
	if (empty($DATA)) {
		$FILE = fopen(DATAFILE, 'c+');
		if (!is_resource($FILE)) {
			return __FUNCTION__." failure ".__LINE__;
		}
		$lock_busy = false;
		$did_lock = flock($FILE, LOCK_EX|LOCK_NB, $lock_busy);
		if (!$did_lock) {
			if ($lock_busy) {
				if ($retries) {
					$retries--;
					fclose($FILE);
					sleep(1);
					return openData($retries);
				}
				return __FUNCTION__." lock failure ".__LINE__;
			}
			return __FUNCTION__." failure ".__LINE__;
		}
		$FILEMTIME = filemtime(DATAFILE);
		$FILESIZE = filesize(DATAFILE);
		$DATA = fread($FILE, MAXDATA);
		while (!feof($FILE) && $DATA < MAXDATA) {
			$DATA .= fread($FILE, MAXDATA);
		}
		$FILEHASH = md5($DATA);
		if ($DATA === '') {
			$DATA = array();
		} else {
			$DATA = json_decode($DATA, true);
			if (is_null($DATA)) {
				return __FUNCTION__." failure ".__LINE__;
			}
		}
	}
	// update $NOW if we had a lock delay
	if ($NOW != time()) $NOW = time();
	
	return true;
}

function pruneData() {
	global $DATA, $NOW;
	$victim = false;
	$victimRequested = $NOW;
	foreach($DATA['logs'] as $k => $v) {
		if ($v['requested'] < $victimRequested) {
			$victimRequested = $v['requested'];
			$victim = $k;
		}
	}
	if ($victim !== false) {
		$DATA['logs'][$victim]['data'] = NULL;
		$DATA['logs'][$victim]['requested'] = false;
	}
}

function saveData($pruneOnOverflow = 5) {
	global $FILE,$FILEMTIME,$FILESIZE,$FILEHASH,$DATA,$VERBOSITY;
	$d = json_encode($DATA);
	// check if content has changed
	$s = strlen($d);
	if ($s == $FILESIZE) {
		$h = md5($d);
		if ($h == $FILEHASH) {
			if ($VERBOSITY >= 1) {
				echo __FUNCTION__." info ".__LINE__.": no changes to save.\n";
			}
			return true;
		}
	}
	// check if content is too large
	if ($s >= MAXDATA) {
		echo __FUNCTION__." failure ".__LINE__.": content is too large.\n";
		if ($pruneOnOverflow) {
			unset($d);
			pruneData();
			return saveData($pruneOnOverflow - 1);
		} else {
			return false;
		}
	}
	// verify file has not changed
	$fm = filemtime(DATAFILE);
	$fs = filesize(DATAFILE);
	if ($fm !== $FILEMTIME || $fs !== $FILESIZE) {
		echo __FUNCTION__." failure ".__LINE__.": file changed externally.\n";
		return false;
	}
	$FILEMTIME = 0;
	$FILESIZE = 0;
	$FILEHASH = "";
	ftruncate($FILE, 0);
	rewind($FILE);
	$w = fwrite($FILE, $d, $s);
	if ($w !== $s) {
		echo __FUNCTION__." failure ".__LINE__.": write length mismatch.\n";
		return false;
	}
	touch(DATAFILE);
	return true;
}

function closeData($doSave = true, $retries = 5) {
	global $FILE, $DATA;
	// attempt to save before closing
	if ($doSave) {
		$saved = saveData();
		if (!$saved) {
			echo "failed to save\n";
			return false;
		}
	}
	// unlock file
	$unlocked = flock($FILE, LOCK_UN);
	if (!$unlocked) {
		echo "failed to unlock\n";
		if ($retries) {
			return closeData(false, $retries - 1);
		}
		return false;
	}
	fclose($FILE);
	$FILE = NULL;
	$DATA = NULL;
	return true;
}

##### CLI FUNCTIONS #####

function getLogFiles() {
	global $DATA;
	// search filesystem for logs to process
	$logGlobs = array(
		'/var/log/httpd/access_log',
		'/var/log/httpd/error_log',
		'/var/log/httpd/ssl_access_log',
		'/var/log/httpd/ssl_error_log',
		'/var/log/php-fpm/error.log',
		'/var/log/php-fpm/www-error.log',
	);
	$logFiles = array();
	foreach($logGlobs as $k => $v) {
		$logFiles = array_merge($logFiles, glob($v));
	}
	$logs = array();
	foreach($logFiles as $k => $v) {
		$logname = $v;
		//$logname = basename($v);
		//$logname = preg_replace('~(\.(log|gz|zip|bz2|xz))+$~', '', $logname);
		//$logname = preg_replace('~^.*[_.]log(-[0-9]+)?$~', '\1', $logname);
		if (preg_match('~^/var/log/([-_a-z]+/[-_a-z]+[._]log)$~', $logname, $m)) {
			$logname = $m[1];
		} else {
			echo "unknown logname: '$logname' from '$v'\n";
			continue;
		}
		$logs[$logname] = array(
			'name' => $logname,
			'file' => $v,
			'requested' => false,
			'data' => NULL,
		);
	}
	if (empty($DATA['logs'])) $DATA['logs'] = array();
	foreach($logs as $k => $v) {
		if (!array_key_exists($k, $DATA['logs'])) {
			$DATA['logs'][$k] = $v;
		}
	}
	ksort($DATA['logs'], SORT_STRING);
}

function findBinary($basename) {
	global $VERBOSITY;
	$paths = array(
		'/bin',
		'/sbin',
		'/usr/bin',
		'/usr/sbin',
		'/usr/local/bin',
		'/usr/local/sbin',
	);
	// TODO: search PATH via: preg_split( $_ENV['PATH'] );
	foreach ($paths as $path) {
		$tfn = $path.'/'.$basename;
		if (!file_exists($tfn)) continue;
		if (!is_executable($tfn)) continue;
		if ($VERBOSITY >= 1) echo "found $basename: $tfn\n";
		return $tfn;
	}
	return false;
}

function updateGunzipBinary() {
	global $GUNZIP;
	if (!empty($GUNZIP)) return $GUNZIP;
	$path = findBinary('gunzip');
	if ($path !== false) {
		$GUNZIP = $path;
		return true;
	}
	return false;
}

function updateLog($id) {
	global $DATA, $GUNZIP, $VERBOSITY;
	
	$lfn = $DATA['logs'][$id]['file'];
	if (!file_exists($lfn)) {
		echo "Failed to read log: file not found.\n";
		return false;
	}
	// get mtime and size of input log file
	$lfm = filemtime($lfn);
	$lfs = filesize($lfn);
	if (!is_readable($lfn)) {
		echo "Failed to read log: file not readable.\n";
		return false;
	}
	if ($lfs >= MAXDATA) {
		echo "log file is too large: $lfs bytes.\n";
		return false;
	}
	if (preg_match('~\.gz$~', $DATA['logs'][$id]['file'])) {
		// build command line for log access
		$LFN = escapeshellarg($lfn);
		$rnd = time() . '-' . random_int(PHP_INT_MIN, PHP_INT_MAX);
		$rnd = dechex(crc32($rnd));
		$tfn = "/tmp/logdata-$rnd.txt";
		$TFN = escapeshellarg($tfn);
		if (empty($GUNZIP)) {
			if (!updateGunzipBinary()) {
				echo "failed to find required gunzip binary.\n";
				return false;
			}
		}
		$CMD = "{$GUNZIP} -cd $LFN > {$TFN}";
		// execute CMD to get temporary output file
		if ($VERBOSITY >= 1) {
			echo "Executing: $CMD\n";
		}
		system($CMD, $ret);
		if ($ret !== 0) {
			echo "Failed to generate data with CMD; error code {$ret}.\n";
			return false;
		}
		$filedata = file_get_contents($TFN);
		// remove temporary output file
		unlink($TFN);
	} else {
		// gather file data
		$filedata = file_get_contents($lfn);
	}
	if (!is_string($filedata)) {
		echo "Failed to read log: file read failed.\n";
		return false;
	}
	$filedata = gzencode($filedata, 9);
	if (!is_string($filedata)) {
		echo "Failed to read log: file data failed to compress.\n";
		return false;
	}
	$filedata = base64_encode($filedata);
	if (!is_string($filedata)) {
		echo "Failed to read log: file data failed to encode.\n";
		return false;
	}
	// store in data array
	$DATA['logs'][$id]['filemtime'] = $lfm;
	$DATA['logs'][$id]['filesize'] = $lfs;
	$DATA['logs'][$id]['data'] = $filedata;
	return true;
}

function updateLogs() {
	global $DATA, $NOW;
	foreach($DATA['logs'] as $k => $v) {
		if (is_null($v['data'])) {
			if (!file_exists($v['file'])) {
				unset($DATA['logs'][$k]);
				continue;
			}
			if ($v['requested'] > 0) {
				updateLog($k);
			}
		} elseif (// when: data older than LIVE_UPDATE
			$NOW - $v['requested'] >= LIVE_UPDATE
			// && refreshed since last mtime
			&& $v['refreshed'] >= $v['filemtime']
			// && refreshed within LIVE_UPDATE
			&& $NOW - $v['refreshed'] <= LIVE_UPDATE
		) {
			// check if log file is modified after last mtime/size
			$lfn = $v['file'];
			$lfm = filemtime($lfn);
			$lfs = filesize($lfn);
			if ($lfm != $v['filemtime'] || $lfs != $v['filesize']) {
				updateLog($k);
			}
		}
	}
}

function cron() {
	global $DATA;
	$result = openData();
	if ($result !== true) {
		echo $result;
		return;
	}
	//var_dump($DATA);
	getLogFiles();
	//var_dump($DATA['logs']);
	updateLogs();
	//var_dump($DATA);
	$saved = saveData();
	closeData(!$saved);
}

function help() {
	$me = basename($GLOBALS['argv'][0]);
	echo "usage: {$me} [options]\n";
	echo "options:\n";
	echo "  -v --verbose  display more output during cron run.\n";
	echo "\n";
	echo "This execution is expected to be from a cron script and will read\n";
	echo "data and perform required operations on file: ".DATAFILE."\n";
	exit(1);
}

function process($argv) {
	global $VERBOSITY;
	$help = false;
	$mode = 'cron';
	
	// parse arguments
	for($i=1; $i < count($argv); $i++) {
		switch($argv[$i]) {
			case '-v':
			case '--verbose':
				$VERBOSITY++;
				break;
			case '-h':
			case '--help':
				$help = true;
				break;
			default:
				echo "invalid argument: {$argv[$i]}\n";
				$help = true;
				break;
		}
	}
	
	// execute 
	if ($help) {
		help();
	} else {
		$mode();
	}
}

##### HTTP FUNCTIONS #####

function dumpSelectedLog() {
	global $DATA, $NOW;
	if (empty($DATA['logs'])) {
		echo "Waiting for cron... Please try again later.";
		return;
	}
	$logname = $_REQUEST['logname'];
	if (empty($logname)) {
		echo "Please select a log first.";
		return;
	}
	if (empty($DATA['logs'][$logname])) {
		echo "Invalid logname: {$logname}\n";
		return;
	}
	$has_data = !is_null($DATA['logs'][$logname]['data']);
	$requested = intval($DATA['logs'][$logname]['requested']);
	if ($has_data) {
		$lastRequested = $NOW - $DATA['logs'][$logname]['requested'];
		$lastRefreshed = $NOW - $DATA['logs'][$logname]['refreshed'];
		if ($lastRequested >= 120 && $lastRefreshed >= 120) {
			$DATA['logs'][$logname]['refreshed'] = $NOW;
		}
		$d = (base64_decode($DATA['logs'][$logname]['data']));
		echo gzinflate(substr($d,10,-8));
	} elseif ($requested === 0) {
		$DATA['logs'][$logname]['requested'] = $NOW;
	} else {
		echo "Waiting for cron... Please try again later.";
	}
	return;
}

function getHtmlForm() {
	global $DATA, $NOW;
	// build options from data
	if (empty($_REQUEST['logname'])) {
		$_REQUEST['logname'] = '';
	}
	if (empty($DATA['logs'])) {
		$k = $_REQUEST['logname'];
		$optionsList = "<option value='{$k}' class='noData' selected>{$k}</option>";
	} else {
		$options = array();
		foreach($DATA['logs'] as $k => $v) {
			$options[$k] = array(
				'has_data' => !is_null($v['data']),
				'selected' => ($k == $_REQUEST['logname']),
			);
		}
		// rebuild into optionsList string
		$optionsList = '';
		foreach($options as $k => $v) {
			$selected = $v['selected'] ? ' selected' : '';
			$cls = $v['has_data'] ? 'hasData' : 'noData';
			$optionsList .= "<option value='{$k}' class='{$cls}'{$selected}>{$k}</option>";
		}
	}
	// verify selected logname is valid
	if (empty($options[$_REQUEST['logname']])) {
		$_REQUEST['logname'] = '';
	}
	// build refresh options
	$refreshOptionsList = '';
	$t = MIN_REFRESH;
	$autorefresh = intval($_REQUEST['autorefresh']);
	if ($autorefresh == 0) $autorefresh = LIVE_UPDATE;
	while ($t <= LIVE_UPDATE) {
		$val = $t;
		$txt = "$t sec";
		$selected = ($val == $autorefresh) ? ' selected' : '';
		$refreshOptionsList .= "<option value='{$val}'{$selected}>{$txt}</option>";
		$t *= 2;
	}
	// add max option (less a few seconds to ensure refreshes are logged before cron runs)
	if (($t / 2) != LIVE_UPDATE) {
		$val = LIVE_UPDATE;
		$txt = "{$val} sec";
		$selected = ($val == $autorefresh) ? ' selected' : '';
		if (!empty($selected)) {
			if (empty($DATA['logs'][$_REQUEST['logname']])) {
				$autorefresh = 20;
			} elseif (empty($DATA['logs'][$_REQUEST['logname']]['filemtime'])) {
				$autorefresh = 20;
			} else {
				$t = $DATA['logs'][$_REQUEST['logname']]['filemtime'] + LIVE_UPDATE;
				// Q: what are we testing for?
				// A: we want to trigger just before mtime+updatetime
				$t -= 15;
				// if its still pending
				if ($t > $NOW) {
					$t -= $NOW;
				} elseif (($NOW - $t) < 20) {
					// if its slightly late, just refresh in 20 sec from now
					$t = 20;
				} else {
					// if its more than 20 seconds too late, wait for the next cycle
					$offset = $DATA['logs'][$_REQUEST['logname']]['filemtime'] % LIVE_UPDATE;
					$t = LIVE_UPDATE + $offset - ($NOW % LIVE_UPDATE) - 15;
					$t %= LIVE_UPDATE;
					if ($t < 20) $t = 20;
				}
				$autorefresh = $t;
			}
			$txt .= " ($autorefresh)";
		}
		$refreshOptionsList .= "<option value='{$val}'{$selected}>{$txt}</option>";
	}
	// add disable option
	$selected = (-1 == $autorefresh) ? ' selected' : '';
	$refreshOptionsList .= "<option value='-1'{$selected}>Disabled</option>";
	// data for form
	if (empty($DATA['logs'])) {
		$doRefresh = 1;
	} else {
		$selectedHasData = empty($DATA['logs'][$_REQUEST['logname']]['data']) ? 0 : 1;
		$doRefresh = ($autorefresh > 0) ? intval(!$selectedHasData) : 0;
	}
	// return HTML content
	return "
		<form id='indexForm' method='POST' action='#'>
			<script>
				var timeout = false;
				var doSubmit = function(){
					if (timeout !== false) {
						clearTimeout(timeout);
					}
					var indexForm = document.getElementById('indexForm');
					indexForm.submit();
				};
				if ($doRefresh != 0) {
					timeout = setTimeout(doSubmit, {$autorefresh}000);
				}
			</script>
			Log: 
			<select name='logname' onChange='doSubmit();'>
				{$optionsList}
			</select>
			Refresh:
			<select name='autorefresh' onChange='doSubmit();'>
				{$refreshOptionsList}
			</select>
		</form>";
}

function render() {
	$result = openData();
	if ($result !== true) echo $result;
?>
<html>
<head>
<style>
body .indexer {
	top:0;
	right:0;
	display: block;
	position: fixed;
	background-color: #ddd;
	border: 3px double silver;
}
body .indexer option {
	background-color: #ddd;
}
body .indexer option.hasData {
	color: #000;
}
body .indexer option.noData {
	color: #999;
}
body .logdata {
	margin-top:35px;
	position: absolute;
	border-top: 1px solid black;
}
</style>
</head><body>
<pre class="logdata">
<?php dumpSelectedLog(); ?>
</pre>
	<div class="indexer">
		<?php echo getHtmlForm(); ?>
	</div>
</body>
</html>
<?php
	if ($result === true) closeData();
}

##### UNIVERSAL FUNCTIONS #####

function main() {
	if (!empty($GLOBALS['argv']) || ($GLOBALS['argc'] > 0)) {
		process($GLOBALS['argv']);
	} else {
		render();
	}
}

main();

?>
