use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

pub struct ScanDb {
    conn: Mutex<Connection>,
    scan_id: String,
}

impl ScanDb {
    pub fn open(db_path: &Path, scan_id: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

        // Migrate old schema: add parent_path column if missing
        let has_parent: bool = conn
            .prepare("SELECT parent_path FROM files LIMIT 0")
            .is_ok();
        if !has_parent {
            let _ = conn.execute(
                "ALTER TABLE files ADD COLUMN parent_path TEXT NOT NULL DEFAULT ''",
                [],
            );
        }

        let has_node_parent: bool = conn
            .prepare("SELECT parent_path FROM nodes LIMIT 0")
            .is_ok();
        if !has_node_parent {
            let _ = conn.execute(
                "ALTER TABLE nodes ADD COLUMN parent_path TEXT NOT NULL DEFAULT ''",
                [],
            );
        }

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                total_size INTEGER DEFAULT 0,
                total_files INTEGER DEFAULT 0,
                total_dirs INTEGER DEFAULT 0,
                skipped INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                path TEXT NOT NULL,
                name TEXT NOT NULL,
                parent_path TEXT DEFAULT '',
                depth INTEGER DEFAULT 0,
                is_dir INTEGER DEFAULT 0,
                size_self INTEGER DEFAULT 0,
                size_total INTEGER DEFAULT 0,
                file_count INTEGER DEFAULT 0,
                dir_count INTEGER DEFAULT 0,
                category TEXT DEFAULT '',
                safety TEXT DEFAULT 'Safe',
                mtime REAL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_nodes_scan_path ON nodes(scan_id, path);
            CREATE INDEX IF NOT EXISTS idx_nodes_scan_parent ON nodes(scan_id, parent_path);
            CREATE INDEX IF NOT EXISTS idx_nodes_scan_parent_size ON nodes(scan_id, parent_path, size_total DESC);
            CREATE INDEX IF NOT EXISTS idx_nodes_scan_depth_size ON nodes(scan_id, depth, size_total DESC);
            CREATE INDEX IF NOT EXISTS idx_nodes_scan_size ON nodes(scan_id, size_total DESC);

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                path TEXT NOT NULL,
                size INTEGER DEFAULT 0,
                parent_path TEXT NOT NULL,
                category TEXT DEFAULT '',
                safety TEXT DEFAULT 'Safe',
                mtime REAL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_files_scan_parent ON files(scan_id, parent_path);
            CREATE INDEX IF NOT EXISTS idx_files_scan_parent_size ON files(scan_id, parent_path, size DESC);
            CREATE INDEX IF NOT EXISTS idx_files_scan_size ON files(scan_id, size DESC);
            CREATE INDEX IF NOT EXISTS idx_files_scan_category ON files(scan_id, category);

            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                name TEXT NOT NULL,
                size INTEGER DEFAULT 0,
                file_count INTEGER DEFAULT 0,
                dir_count INTEGER DEFAULT 0
            );",
        )?;

        Ok(ScanDb {
            conn: Mutex::new(conn),
            scan_id: scan_id.to_string(),
        })
    }

    /// Insert a batch of directory nodes.
    /// Each item: (path, name, parent_path, depth, size_self, size_total, file_count, dir_count, category, safety, mtime)
    pub fn insert_nodes_batch(&self, nodes: &[(String, String, String, i64, i64, i64, i64, i64, String, String, f64)]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO nodes (scan_id, path, name, parent_path, depth, is_dir, size_self, size_total, file_count, dir_count, category, safety, mtime)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
            )?;
            for (path, name, parent_path, depth, size_self, size_total, file_count, dir_count, cat, safety, mtime) in nodes {
                stmt.execute(params![
                    self.scan_id, path, name, parent_path, depth,
                    size_self, size_total, file_count, dir_count,
                    cat, safety, mtime
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Insert file entries.
    pub fn insert_files_batch(&self, files: &[(String, i64, String, String, String, f64)]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO files (scan_id, path, size, parent_path, category, safety, mtime)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            )?;
            for (path, size, parent_path, cat, safety, mtime) in files {
                stmt.execute(params![self.scan_id, path, size, parent_path, cat, safety, mtime])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Write scan summary and clean up old scans (keep last 2).
    pub fn finish_scan(&self, total_size: i64, total_files: i64, total_dirs: i64, skipped: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO scans (scan_id, total_size, total_files, total_dirs, skipped)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![self.scan_id, total_size, total_files, total_dirs, skipped],
        )?;
        // Keep only the 2 most recent scans
        conn.execute_batch(
            "DELETE FROM nodes WHERE scan_id NOT IN (SELECT scan_id FROM scans ORDER BY created_at DESC LIMIT 2);
             DELETE FROM files WHERE scan_id NOT IN (SELECT scan_id FROM scans ORDER BY created_at DESC LIMIT 2);
             DELETE FROM categories WHERE scan_id NOT IN (SELECT scan_id FROM scans ORDER BY created_at DESC LIMIT 2);
             DELETE FROM scans WHERE scan_id NOT IN (SELECT scan_id FROM scans ORDER BY created_at DESC LIMIT 2);"
        )?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Remove old scan data before re-scanning the same scan_id.
    pub fn clear_scan(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM nodes WHERE scan_id = ?1", params![self.scan_id])?;
        conn.execute("DELETE FROM files WHERE scan_id = ?1", params![self.scan_id])?;
        conn.execute("DELETE FROM categories WHERE scan_id = ?1", params![self.scan_id])?;
        conn.execute("DELETE FROM scans WHERE scan_id = ?1", params![self.scan_id])?;
        // Insert placeholder so FK constraints on nodes/files are satisfied
        conn.execute(
            "INSERT INTO scans (scan_id, total_size, total_files, total_dirs, skipped) VALUES (?1, 0, 0, 0, 0)",
            params![self.scan_id],
        )?;
        Ok(())
    }
}
