app.get("/u", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  res.json(rows);
});
