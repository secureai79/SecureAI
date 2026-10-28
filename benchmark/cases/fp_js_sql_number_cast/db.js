await db.query(`SELECT * FROM items LIMIT ${Number(limit)}`);
