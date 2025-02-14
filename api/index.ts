import express, { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import joi from 'joi';
import cors from 'cors';

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

const MEMORY_DB: Record<string, UserEntry> = {};

const userSchema = joi.object({
  username: joi.string().min(3).max(24).required(),
  email: joi.string().email().required(),
  type: joi.string().valid('user', 'admin').required(),
  password: joi
    .string()
    .min(5)
    .max(24)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).*$/)
    .required(),
});

app.get('/', (req: Request, res: Response) => {
  res.json({ message: 'Welcome to the Vercel Express API' });
});

app.post('/register', async (req: Request, res: Response) => {
  const { username, email, type, password } = req.body;
  const { error } = userSchema.validate({ username, email, type, password });

  if (error) return res.status(400).json({ message: error.details[0].message });

  if (MEMORY_DB[email]) return res.status(409).json({ message: 'User exists!' });

  const salt = await bcrypt.genSalt(10);
  const passwordhash = await bcrypt.hash(password, salt);
  MEMORY_DB[email] = { email, type, salt, passwordhash };

  res.status(201).json({ message: 'User registered successfully!' });
});

app.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;
  const user = Object.values(MEMORY_DB).find((user) => user.email === username);

  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  const isMatch = await bcrypt.compare(password, user.passwordhash);
  if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

  res.status(200).json({ message: 'Login successful' });
});

export default app;
