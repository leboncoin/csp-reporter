#!/usr/bin/env python3
"""
SQLITE
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
        self.cur.execute('CREATE TABLE IF NOT EXISTS '+table_name+' (BlockedURI TEXT NOT NULL PRIMARY KEY, DocumentURI TEXT NOT NULL, FirstSeen TEXT NOT NULL, LastSeen TEXT NOT NULL)')

    def sqlite_insert(self, table_name, blocked_uri, document_uri, firstseen, lastseen):
        """
        Insert new entry infos
        """
        self.cur.execute('INSERT OR IGNORE INTO '+table_name+' (BlockedURI, DocumentURI, FirstSeen, LastSeen) VALUES (?,?,?,?);', (blocked_uri, document_uri, firstseen, lastseen))
        self.conn.commit()

    def sqlite_verify_entry(self, table_name, blocked_uri):
        """
        Verify if entry still exist
        """
        res = self.cur.execute('SELECT EXISTS (SELECT 1 FROM '+table_name+' WHERE BlockedURI='+"\""+blocked_uri+"\""+' LIMIT 1);')
        fres = res.fetchone()[0]
        if fres != 0:
            return 1
        return 0

    def sqlite_update_lastseen(self, table_name, blocked_uri, lastseen):
        """
        Update lastseen
        """
        self.cur.execute('UPDATE '+table_name+' SET lastseen=? WHERE BlockedURI=?;', (lastseen, blocked_uri))
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
