import mysql from 'mysql2/promise';

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

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
    result_filenames: string;
    created_at: Date;
}

export async function query<T>(sql: string, params?: unknown[]): Promise<T> {
    const [rows] = await pool.execute(sql, params);
    return rows as T;
}

/** Temporary: test that the DB is reachable. Throws on failure. */
export async function testConnection(): Promise<{ ok: true; message: string }> {
    const conn = await pool.getConnection();
    try {
        await conn.ping();
        return { ok: true, message: 'Database connection successful.' };
    } finally {
        conn.release();
    }
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
    const [result] = await pool.execute(
        'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
        [email.trim().toLowerCase(), passwordHash, role]
    );
    return (result as mysql.ResultSetHeader).insertId;
}

export async function countUsers(): Promise<number> {
    const rows = await query<{ cnt: number }[]>('SELECT COUNT(*) AS cnt FROM users');
    return rows[0]?.cnt ?? 0;
}

export async function insertTryOnHistory(
    userId: number,
    generationId: number,
    personFilename: string,
    productFilename: string,
    resultFilenames: string[]
): Promise<number> {
    const [result] = await pool.execute(
        'INSERT INTO try_on_history (user_id, generation_id, person_filename, product_filename, result_filenames) VALUES (?, ?, ?, ?, ?)',
        [userId, generationId, personFilename, productFilename, JSON.stringify(resultFilenames)]
    );
    return (result as mysql.ResultSetHeader).insertId;
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
    const [result] = await pool.execute('DELETE FROM try_on_history WHERE generation_id = ?', [generationId]);
    return (result as mysql.ResultSetHeader).affectedRows > 0;
}

export { pool };
