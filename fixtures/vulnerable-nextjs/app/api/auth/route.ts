import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  const body = await request.json();
  const token = 'ghp_fakeToken12345678901234567890123456';

  // Logging sensitive authorization token and entire process.env
  console.log('Generated user authToken:', token);
  console.log(process.env);

  return NextResponse.json({ success: true });
}
