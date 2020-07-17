#!/usr/bin/env python3
"""
SQLITE

Copyright (c) 2020 leboncoin
MIT License
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)

"""

# Third party library imports
import sqlite3

class SqliteCmd():
    """
    Sqlite3 DB commands
    """
    def __init__(self, DBfile):
        self.conn = sqlite3.connect(DBfile)
        self.cur = self.conn.cursor()

    def sqlite_create_table(self, table_name):
        """
        Creating main Table if not exist
        """
        self.cur.execute('CREATE TABLE IF NOT EXISTS '+table_name+' (\
                BlockedURI TEXT NOT NULL,\
                ViolatedDirective TEXT NOT NULL,\
                DocumentURI TEXT NOT NULL,\
                FirstSeen TEXT NOT NULL,\
                LastSeen TEXT NOT NULL,\
                ColumnNumber TEXT,\
                LineNumber TEXT,\
                Referrer TEXT,\
                ScriptSample TEXT,\
                Status TEXT NOT NULL,\
                PRIMARY KEY (BlockedURI, ViolatedDirective))')

    def sqlite_insert(self, table_name, blocked_uri, violated_directive, document_uri, firstseen, lastseen, column_n, line_n, referrer, script_sample):
        """
        Insert new entry infos
        """
        self.cur.execute('INSERT OR IGNORE INTO '+table_name+' (\
                BlockedURI,\
                ViolatedDirective,\
                DocumentURI,\
                FirstSeen,\
                LastSeen,\
                ColumnNumber,\
                LineNumber,\
                Referrer,\
                ScriptSample,\
                Status) VALUES (?,?,?,?,?,?,?,?,?, "new");', (blocked_uri, violated_directive, document_uri, firstseen, lastseen, column_n, line_n, referrer, script_sample))
        self.conn.commit()

    def sqlite_verify_entry(self, table_name, blocked_uri, violated_directive):
        """
        Verify if entry still exist
        """
        res = self.cur.execute('SELECT EXISTS (SELECT 1 FROM '+table_name+' WHERE BlockedURI=? AND ViolatedDirective=? LIMIT 1);', (blocked_uri,violated_directive))
        fres = res.fetchone()[0]
        if fres != 0:
            return 1
        return 0

    def sqlite_update_lastseen(self, table_name, blocked_uri, violated_directive, lastseen):
        """
        Update lastseen
        """
        self.cur.execute('UPDATE '+table_name+' SET lastseen=? WHERE BlockedURI=? AND ViolatedDirective=?;', (lastseen, blocked_uri, violated_directive))
        self.conn.commit()

    def __del__(self):
        try:
            self.cur.close()
            self.conn.close()
        except:
            pass

    def sqlite_close(self):
        """
        Close
        """
        self.__del__()
