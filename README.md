# phplog-frontend
Provides simple access to httpd/php-fpm logs using cron and PHP.  Provides caching, log switching, garbage collection and permissions restriction (via .htaccess/.htpasswd).

GitHub Home: https://github.com/gissf1/phplog-frontend/

## Features
- cron-based log data acquisition
- cached log data for faster rendering
- support for transparently decompressing .gz compressed log files using ```gunzip -cd```
- ability to select an automated refresh interval (for both error recovery and information updates)
- compress log content for reduced storage requirements
- consolidated data location (a single state file)
- locking and error reporting

## Usage
- The repository contents are placed in a web server directory with PHP enabled
- source apache/php-fpm log files should be readable by the cron process user
- a configuration/state file is created with permissions writable by the web server process, as well as permissions writable by the cron process user.  By default, this file is named ".data.json" in the repository directory.
- add a ".htpasswd" file to the repository directory for access control, or edit the ".htaccess" file according to security preferences.
- setup cron with a rule like: ```*/5 * * * *  /usr/bin/php /var/www/html/phplog-frontend/index.php```

## Known Issues
- This has not been tested with selnux enabled.  There may be additional rules or configuration required to use under this environment.  Please send pull requests for improvements to this.
- The log data is delayed because it is expected for this to be gathered via cron, and does not collect log data with a process socket.  (Patches for a pure live mode are welcome)
