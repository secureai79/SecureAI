const rows = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
