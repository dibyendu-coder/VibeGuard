import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';

const app = express();

app.use(helmet());

// Secure CORS configuration with restricted origin
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');
  next();
});

// Parameterized query avoiding SQL injection
app.get('/api/users/:id', async (req: Request, res: Response) => {
  const userId = req.params.id;

  // Proper session verification
  if (!(req as any).session?.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const result = await (global as any).db.query('SELECT id, username, email FROM users WHERE id = $1', [userId]);
  return res.json({ user: result.rows[0] });
});

// Sanitized production error handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  // Never leak internal stack trace to client
  res.status(500).json({ error: 'Internal Server Error' });
});

export default app;
