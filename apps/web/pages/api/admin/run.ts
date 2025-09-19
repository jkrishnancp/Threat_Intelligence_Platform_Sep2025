import type { NextApiRequest, NextApiResponse } from 'next';
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).end();
  const kind = (req.query.kind as string) || 'NVD';
  const token = process.env.INTERNAL_SERVICE_TOKEN as string;
  const api = process.env.NEXT_PUBLIC_API_URL as string;
  const r = await fetch(`${api}/admin/run/${kind}?token=${token}`, { method: 'POST' });
  const j = await r.json();
  res.status(200).json(j);
}