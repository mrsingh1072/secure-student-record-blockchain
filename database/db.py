"""
MySQL-backed DatabaseManager for Secure Student Record Blockchain.

This implementation assumes the database and tables already exist.
It does not create or migrate schema. Queries are parameterized and
results are returned as dictionaries via PyMySQL's DictCursor.
"""

import os
from contextlib import contextmanager
from datetime import datetime, timezone

import pymysql
import pymysql.cursors


def _get_db_config() -> dict:
    """Build MySQL connection settings from environment variables."""
    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "port": int(os.environ.get("DB_PORT", 3306)),
        "user": os.environ.get("DB_USER", "root"),
        "password": os.environ.get("DB_PASSWORD", "@trimurti123"),
        "database": os.environ.get("DB_NAME", "ssrbc"),
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": False,
    }


class DatabaseManager:
    """Central MySQL persistence layer used across the application."""

    def __init__(self):
        self._config = _get_db_config()
        self.connection = self._connect()
        self._table_columns_cache = {}

    def _connect(self):
        return pymysql.connect(**self._config)

    def _ensure_connection(self):
        try:
            self.connection.ping(reconnect=True)
        except Exception:
            self.connection = self._connect()

    @contextmanager
    def _cursor(self):
        self._ensure_connection()
        cursor = self.connection.cursor()
        try:
            yield cursor
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def get_connection(self):
        self._ensure_connection()
        return self.connection

    def _get_table_columns(self, table_name: str) -> set:
        """Inspect existing table columns once and cache them."""
        if table_name not in self._table_columns_cache:
            with self._cursor() as cursor:
                cursor.execute(f"SHOW COLUMNS FROM {table_name}")
                self._table_columns_cache[table_name] = {
                    row["Field"] for row in cursor.fetchall()
                }
        return self._table_columns_cache[table_name]

    def _table_has_column(self, table_name: str, column_name: str) -> bool:
        return column_name in self._get_table_columns(table_name)

    def _normalize_user_row(self, row: dict) -> dict:
        if not row:
            return None

        row.setdefault("student_id", None)
        row.setdefault("updated_at", row.get("created_at"))
        row.setdefault("is_active", 1)
        return row

    def _normalize_record_row(self, row: dict) -> dict:
        if not row:
            return None

        row.setdefault("blockchain_hash", None)
        row.setdefault("created_by", None)
        row.setdefault("updated_at", row.get("created_at"))
        row.setdefault("is_verified", 0)
        return row

    def _rows_to_records(self, rows: list) -> list:
        return [self._normalize_record_row(dict(row)) for row in rows]

    def create_user(self, username: str, email: str, password_hash: str,
                    role: str, student_id: str = None) -> int:
        """Insert a new user and return the generated primary key."""
        columns = ["username", "email", "password_hash", "role"]
        values = [username, email, password_hash, role]

        if self._table_has_column("users", "student_id"):
            columns.append("student_id")
            values.append(student_id)

        placeholders = ", ".join(["%s"] * len(columns))
        sql = f"""
            INSERT INTO users ({', '.join(columns)})
            VALUES ({placeholders})
        """

        with self._cursor() as cursor:
            cursor.execute(sql, tuple(values))
            return cursor.lastrowid

    def get_user_by_username(self, username: str) -> dict:
        """Return one user row as a dictionary, or None if not found."""
        filters = ["username = %s"]
        params = [username]

        if self._table_has_column("users", "is_active"):
            filters.append("is_active = 1")

        sql = f"""
            SELECT *
            FROM users
            WHERE {' AND '.join(filters)}
            LIMIT 1
        """

        with self._cursor() as cursor:
            cursor.execute(sql, tuple(params))
            row = cursor.fetchone()
            return self._normalize_user_row(row)

    def create_student_record(self, student_id: str, record_type: str,
                              encrypted_data: str, data_hash: str,
                              created_by: str = None) -> int:
        """Insert an encrypted student record and return the record ID."""
        columns = ["student_id", "record_type", "encrypted_data", "data_hash"]
        values = [student_id, record_type, encrypted_data, data_hash]

        if self._table_has_column("student_records", "created_by"):
            columns.append("created_by")
            values.append(created_by)

        placeholders = ", ".join(["%s"] * len(columns))
        sql = f"""
            INSERT INTO student_records ({', '.join(columns)})
            VALUES ({placeholders})
        """

        with self._cursor() as cursor:
            cursor.execute(sql, tuple(values))
            return cursor.lastrowid

    def get_student_records_by_student_id(self, student_id: str,
                                          record_type: str = None) -> list:
        """Return matching student records as a list of dictionaries."""
        filters = ["student_id = %s"]
        params = [student_id]

        if record_type is not None:
            filters.append("record_type = %s")
            params.append(record_type)

        sql = f"""
            SELECT *
            FROM student_records
            WHERE {' AND '.join(filters)}
            ORDER BY created_at DESC, id DESC
        """

        with self._cursor() as cursor:
            cursor.execute(sql, tuple(params))
            return self._rows_to_records(cursor.fetchall())

    def get_student_records(self, student_id: str, record_type: str = None) -> list:
        """Backward-compatible alias used by the existing model layer."""
        return self.get_student_records_by_student_id(student_id, record_type)

    def update_blockchain_hash(self, record_id: int, blockchain_hash: str) -> bool:
        """Update blockchain metadata for a stored student record."""
        assignments = []
        params = []

        if self._table_has_column("student_records", "blockchain_hash"):
            assignments.append("blockchain_hash = %s")
            params.append(blockchain_hash)

        if self._table_has_column("student_records", "is_verified"):
            assignments.append("is_verified = %s")
            params.append(1)

        if not assignments:
            return False

        params.append(record_id)
        sql = f"""
            UPDATE student_records
            SET {', '.join(assignments)}
            WHERE id = %s
        """

        with self._cursor() as cursor:
            cursor.execute(sql, tuple(params))
            return cursor.rowcount > 0

    def get_database_stats(self) -> dict:
        """Return aggregated database statistics for dashboards and health checks."""
        stats = {
            "total_records": 0,
            "verified_records": 0,
            "total_users": 0,
            "total_permissions": 0,
            "total_audit_logs": 0,
        }

        with self._cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS count FROM student_records")
            stats["total_records"] = cursor.fetchone()["count"]

            if self._table_has_column("student_records", "is_verified"):
                cursor.execute(
                    "SELECT COUNT(*) AS count FROM student_records WHERE is_verified = %s",
                    (1,),
                )
                stats["verified_records"] = cursor.fetchone()["count"]
            elif self._table_has_column("student_records", "blockchain_hash"):
                cursor.execute(
                    "SELECT COUNT(*) AS count FROM student_records WHERE blockchain_hash IS NOT NULL"
                )
                stats["verified_records"] = cursor.fetchone()["count"]

            user_sql = "SELECT COUNT(*) AS count FROM users"
            if self._table_has_column("users", "is_active"):
                user_sql += " WHERE is_active = 1"
            cursor.execute(user_sql)
            stats["total_users"] = cursor.fetchone()["count"]

            permission_sql = "SELECT COUNT(*) AS count FROM access_permissions"
            if self._table_has_column("access_permissions", "is_active"):
                permission_sql += " WHERE is_active = 1"
            cursor.execute(permission_sql)
            stats["total_permissions"] = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) AS count FROM audit_logs")
            stats["total_audit_logs"] = cursor.fetchone()["count"]

        stats["total_access_logs"] = stats["total_audit_logs"]
        return stats

    def log_access_attempt(self, student_id: str = None, accessor_username: str = None,
                           record_id=None, action: str = None, access_granted: bool = None,
                           ip_address: str = None, user_agent: str = None,
                           username: str = None, resource: str = None,
                           status: str = None) -> None:
        """
        Write an audit entry to the existing audit_logs table.

        Supports both the current project call signature and a simplified
        `(username, action, resource, status)` style via keyword arguments.
        """
        audit_columns = self._get_table_columns("audit_logs")

        resolved_username = accessor_username or username or "system"
        resolved_action = action or "UNKNOWN"
        resolved_resource = resource
        if resolved_resource is None:
            resource_parts = []
            if student_id:
                resource_parts.append(f"student:{student_id}")
            if record_id is not None:
                resource_parts.append(f"record:{record_id}")
            resolved_resource = " | ".join(resource_parts) if resource_parts else "system"

        if status is None:
            if access_granted is None:
                resolved_status = "UNKNOWN"
            else:
                resolved_status = "SUCCESS" if access_granted else "FAILED"
        else:
            resolved_status = status

        insert_data = {}
        if "username" in audit_columns:
            insert_data["username"] = resolved_username
        if "accessor_username" in audit_columns:
            insert_data["accessor_username"] = resolved_username
        if "action" in audit_columns:
            insert_data["action"] = resolved_action
        if "resource" in audit_columns:
            insert_data["resource"] = resolved_resource
        if "status" in audit_columns:
            insert_data["status"] = resolved_status
        if "student_id" in audit_columns:
            insert_data["student_id"] = student_id or "N/A"
        if "record_id" in audit_columns:
            insert_data["record_id"] = record_id
        if "access_granted" in audit_columns:
            insert_data["access_granted"] = 1 if access_granted else 0
        if "ip_address" in audit_columns:
            insert_data["ip_address"] = ip_address
        if "user_agent" in audit_columns:
            insert_data["user_agent"] = user_agent[:512] if user_agent else None

        columns = list(insert_data.keys())
        placeholders = ", ".join(["%s"] * len(columns))
        sql = f"""
            INSERT INTO audit_logs ({', '.join(columns)})
            VALUES ({placeholders})
        """

        with self._cursor() as cursor:
            cursor.execute(sql, tuple(insert_data[column] for column in columns))

    def check_access_permission(self, student_id: str, verifier_username: str,
                                resource_type: str = None) -> bool:
        """Return True if a valid verifier permission exists for the student."""
        filters = ["student_id = %s", "verifier_username = %s"]
        params = [student_id, verifier_username]
        columns = self._get_table_columns("access_permissions")

        if "is_active" in columns:
            filters.append("is_active = 1")

        if "expires_at" in columns:
            filters.append("(expires_at IS NULL OR expires_at > %s)")
            params.append(datetime.now(timezone.utc))

        if "resource_type" in columns and resource_type is not None:
            filters.append("(resource_type IS NULL OR resource_type = %s)")
            params.append(resource_type)

        sql = f"""
            SELECT COUNT(*) AS count
            FROM access_permissions
            WHERE {' AND '.join(filters)}
        """

        with self._cursor() as cursor:
            cursor.execute(sql, tuple(params))
            row = cursor.fetchone()
            return row["count"] > 0

    def grant_access_permission(self, student_id: str, verifier_username: str,
                                resource_type: str = None, expires_at=None) -> bool:
        """Create or refresh a verifier permission row."""
        columns = self._get_table_columns("access_permissions")

        match_filters = ["student_id = %s", "verifier_username = %s"]
        match_params = [student_id, verifier_username]

        if "resource_type" in columns:
            if resource_type is None:
                match_filters.append("resource_type IS NULL")
            else:
                match_filters.append("resource_type = %s")
                match_params.append(resource_type)

        update_assignments = []
        update_params = []
        if "expires_at" in columns:
            update_assignments.append("expires_at = %s")
            update_params.append(expires_at)
        if "is_active" in columns:
            update_assignments.append("is_active = %s")
            update_params.append(1)

        if update_assignments:
            update_sql = f"""
                UPDATE access_permissions
                SET {', '.join(update_assignments)}
                WHERE {' AND '.join(match_filters)}
            """
            with self._cursor() as cursor:
                cursor.execute(update_sql, tuple(update_params + match_params))
                if cursor.rowcount > 0:
                    return True

        insert_columns = ["student_id", "verifier_username"]
        insert_values = [student_id, verifier_username]

        if "resource_type" in columns:
            insert_columns.append("resource_type")
            insert_values.append(resource_type)
        if "expires_at" in columns:
            insert_columns.append("expires_at")
            insert_values.append(expires_at)
        if "is_active" in columns:
            insert_columns.append("is_active")
            insert_values.append(1)

        placeholders = ", ".join(["%s"] * len(insert_columns))
        insert_sql = f"""
            INSERT INTO access_permissions ({', '.join(insert_columns)})
            VALUES ({placeholders})
        """

        with self._cursor() as cursor:
            cursor.execute(insert_sql, tuple(insert_values))
            return cursor.rowcount > 0

    def revoke_access_permission(self, student_id: str, verifier_username: str,
                                 resource_type: str = None) -> bool:
        """Deactivate or delete a verifier permission row."""
        columns = self._get_table_columns("access_permissions")
        filters = ["student_id = %s", "verifier_username = %s"]
        params = [student_id, verifier_username]

        if "resource_type" in columns and resource_type is not None:
            filters.append("resource_type = %s")
            params.append(resource_type)

        if "is_active" in columns:
            sql = f"""
                UPDATE access_permissions
                SET is_active = %s
                WHERE {' AND '.join(filters)}
            """
            params = [0] + params
        else:
            sql = f"""
                DELETE FROM access_permissions
                WHERE {' AND '.join(filters)}
            """

        with self._cursor() as cursor:
            cursor.execute(sql, tuple(params))
            return cursor.rowcount > 0

    def search_student_records(self, student_id: str = None, record_type: str = None,
                               created_by: str = None, date_from: str = None,
                               date_to: str = None, limit: int = 100) -> list:
        """Admin-facing search helper used by the existing search route."""
        filters = []
        params = []
        columns = self._get_table_columns("student_records")

        if student_id:
            filters.append("student_id = %s")
            params.append(student_id)
        if record_type:
            filters.append("record_type = %s")
            params.append(record_type)
        if created_by and "created_by" in columns:
            filters.append("created_by = %s")
            params.append(created_by)
        if date_from and "created_at" in columns:
            filters.append("created_at >= %s")
            params.append(date_from)
        if date_to and "created_at" in columns:
            filters.append("created_at <= %s")
            params.append(date_to)

        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        sql = f"""
            SELECT *
            FROM student_records
            {where_clause}
            ORDER BY created_at DESC, id DESC
            LIMIT %s
        """
        params.append(limit)

        with self._cursor() as cursor:
            cursor.execute(sql, tuple(params))
            return self._rows_to_records(cursor.fetchall())
