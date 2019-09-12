# goaccess-frontend
Provides perpetual apache log statistics using cron, PHP, and goaccess.  Provides caching, log switching, garbage collection and permissions restriction.

GitHub Home: https://github.com/gissf1/goaccess-frontend/

## Features
- cron-based log data acquisition
- cached log summaries for any historical (non-live) log files
- support for transparently decompressing .gz compressed log files using ```gunzip -cd```
- ability to select an automated refresh interval (for both error recovery and information updates)
- compress html content for reduced storage requirements
- consolidated data location (a single state file)
- locking and error reporting

## Usage
- The repository contents are placed in a web server directory with PHP enabled
- source apache log files should be readable by the cron process user
- a configuration/state file is created with permissions writable by the web server process, as well as permissions writable by the cron process user.  By default, this file is named ".data.json" in the repository directory.
- add a ".htpasswd" file to the repository directory for access control, or edit the ".htaccess" file according to security preferences.
- setup cron with a rule like: ```*/5 * * * *  /usr/bin/php /var/www/html/goaccess-frontend/index.php```

## Known Issues
- This has not been tested with selnux enabled.  There may be additional rules or configuration required to use under this environment.  Please send pull requests for improvements to this.
- The data on the "live" view is delayed because it is expected for this to be gathered via cron, and not with a live process hosting a data socket.  (Patches for a pure live mode are welcome)
