import mysql from 'mysql2/promise';
import pg from 'pg';

const usePostgres = !!process.env.DATABASE_URL;

// ----------------------------------------------------------------------------
// MySQL pool (when DATABASE_URL is not set)
// ----------------------------------------------------------------------------
const mysqlPool = usePostgres
    ? null
    : mysql.createPool({
          host: process.env.DB_HOST || 'localhost',
          port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 3306,
          user: process.env.DB_USER,
          password: process.env.DB_PASSWORD,
          database: process.env.DB_NAME,
          waitForConnections: true,
          connectionLimit: 10,
          queueLimit: 0,
      });

// ----------------------------------------------------------------------------
// PostgreSQL pool (when DATABASE_URL is set - Render, Railway, etc.)
// ----------------------------------------------------------------------------
const pgPool = usePostgres ? new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }) : null;

export interface User {
    id: number;
    email: string;
    password_hash: string;
    role: 'user' | 'superadmin';
    created_at: Date;
}

export interface TryOnHistoryRow {
    id: number;
    user_id: number;
    generation_id: number;
    person_filename: string;
    product_filename: string;
    /** MySQL: JSON string; PostgreSQL: parsed array (JSONB) */
    result_filenames: string | string[];
    created_at: Date;
}

/** Convert MySQL-style ? placeholders to pg $1, $2, ... */
function toPgParams(sql: string): string {
    let n = 0;
    return sql.replace(/\?/g, () => `$${++n}`);
}

async function query<T>(sql: string, params?: unknown[]): Promise<T> {
    if (usePostgres && pgPool) {
        const pgSql = toPgParams(sql);
        const result = await pgPool.query(pgSql, params ?? []);
        return result.rows as T;
    }
    if (mysqlPool) {
        const [rows] = await mysqlPool.execute(sql, params ?? []);
        return rows as T;
    }
    throw new Error('No database configured. Set DATABASE_URL (Postgres) or DB_HOST/DB_USER/DB_PASSWORD/DB_NAME (MySQL).');
}

/** Temporary: test that the DB is reachable. Throws on failure. */
export async function testConnection(): Promise<{ ok: true; message: string }> {
    if (usePostgres && pgPool) {
        await pgPool.query('SELECT 1');
        return { ok: true, message: 'Database connection successful.' };
    }
    if (mysqlPool) {
        const conn = await mysqlPool.getConnection();
        try {
            await conn.ping();
            return { ok: true, message: 'Database connection successful.' };
        } finally {
            conn.release();
        }
    }
    throw new Error('No database configured.');
}

export async function getUserByEmail(email: string): Promise<User | null> {
    const rows = await query<User[]>('SELECT id, email, password_hash, role, created_at FROM users WHERE email = ?', [email.trim().toLowerCase()]);
    return rows.length > 0 ? rows[0] : null;
}

export async function getUserById(id: number): Promise<User | null> {
    const rows = await query<User[]>('SELECT id, email, password_hash, role, created_at FROM users WHERE id = ?', [id]);
    return rows.length > 0 ? rows[0] : null;
}

export async function createUser(email: string, passwordHash: string, role: 'user' | 'superadmin' = 'user'): Promise<number> {
    const e = email.trim().toLowerCase();
    if (usePostgres && pgPool) {
        const result = await pgPool.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
            [e, passwordHash, role]
        );
        return result.rows[0]?.id ?? 0;
    }
    if (mysqlPool) {
        const [result] = await mysqlPool.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)', [e, passwordHash, role]);
        return (result as mysql.ResultSetHeader).insertId;
    }
    throw new Error('No database configured.');
}

export async function countUsers(): Promise<number> {
    const rows = await query<{ cnt: string }[]>('SELECT COUNT(*) AS cnt FROM users');
    const cnt = rows[0]?.cnt;
    return typeof cnt === 'string' ? parseInt(cnt, 10) : Number(cnt) ?? 0;
}

export async function insertTryOnHistory(
    userId: number,
    generationId: number,
    personFilename: string,
    productFilename: string,
    resultFilenames: string[]
): Promise<number> {
    const json = JSON.stringify(resultFilenames);
    if (usePostgres && pgPool) {
        const result = await pgPool.query(
            'INSERT INTO try_on_history (user_id, generation_id, person_filename, product_filename, result_filenames) VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING id',
            [userId, generationId, personFilename, productFilename, json]
        );
        return result.rows[0]?.id ?? 0;
    }
    if (mysqlPool) {
        const [result] = await mysqlPool.execute(
            'INSERT INTO try_on_history (user_id, generation_id, person_filename, product_filename, result_filenames) VALUES (?, ?, ?, ?, ?)',
            [userId, generationId, personFilename, productFilename, json]
        );
        return (result as mysql.ResultSetHeader).insertId;
    }
    throw new Error('No database configured.');
}

export async function getTryOnHistoryByUser(userId: number, isSuperadmin: boolean): Promise<TryOnHistoryRow[]> {
    if (isSuperadmin) {
        return query<TryOnHistoryRow[]>(
            'SELECT id, user_id, generation_id, person_filename, product_filename, result_filenames, created_at FROM try_on_history ORDER BY created_at DESC'
        );
    }
    return query<TryOnHistoryRow[]>(
        'SELECT id, user_id, generation_id, person_filename, product_filename, result_filenames, created_at FROM try_on_history WHERE user_id = ? ORDER BY created_at DESC',
        [userId]
    );
}

export async function getTryOnByGenerationId(generationId: number): Promise<TryOnHistoryRow | null> {
    const rows = await query<TryOnHistoryRow[]>(
        'SELECT id, user_id, generation_id, person_filename, product_filename, result_filenames, created_at FROM try_on_history WHERE generation_id = ?',
        [generationId]
    );
    return rows.length > 0 ? rows[0] : null;
}

export async function deleteTryOnHistory(generationId: number): Promise<boolean> {
    if (usePostgres && pgPool) {
        const result = await pgPool.query('DELETE FROM try_on_history WHERE generation_id = $1', [generationId]);
        return (result.rowCount ?? 0) > 0;
    }
    if (mysqlPool) {
        const [result] = await mysqlPool.execute('DELETE FROM try_on_history WHERE generation_id = ?', [generationId]);
        return (result as mysql.ResultSetHeader).affectedRows > 0;
    }
    return false;
}

export const pool = pgPool ?? mysqlPool;
