import pg from 'pg';

const { Pool } = pg;
let pool = null;
let ready = false;
let lastError = null;
let saveChain = Promise.resolve();

export function databaseConfigured(){ return Boolean(process.env.DATABASE_URL); }

export async function initDatabase({ getState, applyState }) {
  if (!databaseConfigured()) return { configured:false, connected:false, reason:'DATABASE_URL belum diisi' };
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized:false },
    max: Number(process.env.DATABASE_POOL_SIZE || 5),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
  });
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS zyrex_state (
      id SMALLINT PRIMARY KEY,
      schema_version INTEGER NOT NULL,
      state JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    const result = await pool.query('SELECT schema_version, state FROM zyrex_state WHERE id=1');
    if (result.rows[0]?.state) applyState(result.rows[0].state);
    ready = true;
    lastError = null;
    return { configured:true, connected:true, schemaVersion: result.rows[0]?.schema_version || null };
  } catch (error) {
    lastError = String(error?.message || error).slice(0,300);
    ready = false;
    return { configured:true, connected:false, reason:lastError };
  }
}

export function databaseStatus(){
  return {
    configured: databaseConfigured(),
    connected: ready,
    lastError,
    driver: 'postgresql'
  };
}

export function saveState(state){
  if (!ready || !pool) return Promise.resolve(false);
  const payload = JSON.stringify(state);
  saveChain = saveChain.then(async()=>{
    try {
      await pool.query(
        `INSERT INTO zyrex_state (id, schema_version, state, updated_at)
         VALUES (1, $1, $2::jsonb, NOW())
         ON CONFLICT (id) DO UPDATE SET schema_version=EXCLUDED.schema_version, state=EXCLUDED.state, updated_at=NOW()`,
        [Number(state.schemaVersion || 1), payload]
      );
      lastError = null;
      return true;
    } catch (error) {
      lastError = String(error?.message || error).slice(0,300);
      return false;
    }
  }).catch(()=>false);
  return saveChain;
}

export async function pingDatabase(){
  if (!ready || !pool) return false;
  try { await pool.query('SELECT 1'); lastError=null; return true; }
  catch(error){ lastError=String(error?.message||error).slice(0,300); return false; }
}

export async function closeDatabase(){ if(pool) await pool.end(); pool=null; ready=false; }
