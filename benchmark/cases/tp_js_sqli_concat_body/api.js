async function find(req, pool) {
  const sql = "SELECT * FROM orders WHERE id = " + req.body.id;
  return pool.query(sql);
}
