import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as dotenv from "dotenv";
import * as schema from "./schema";

dotenv.config();

const connectionString =
  process.env.DATABASE_URL || "postgresql://postgres:postgres@localhost:5432/soc_assistant";

export const pool = new pg.Pool({
  connectionString,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on("error", (err) => {
  console.error("Unexpected error on idle PostgreSQL client:", err);
});

export const db = drizzle(pool, { schema });

/**
 * Validates the PostgreSQL connection.
 * Throws a descriptive error if PostgreSQL is unreachable.
 */
export async function checkDatabaseConnection(): Promise<{ ok: boolean; latencyMs: number; error?: string }> {
  const start = Date.now();
  try {
    const client = await pool.connect();
    try {
      await client.query("SELECT 1");
      const latencyMs = Date.now() - start;
      return { ok: true, latencyMs };
    } finally {
      client.release();
    }
  } catch (err: any) {
    const message = `PostgreSQL database unavailable at ${connectionString.replace(/:[^:@]+@/, ":***@")}: ${err.message}`;
    console.error(`[Database Error] ${message}`);
    return { ok: false, latencyMs: Date.now() - start, error: message };
  }
}
