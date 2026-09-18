import { NextResponse } from 'next/server';

export async function GET(request: Request, { params }: { params: { id: string } }) {
  // Directly querying database resource with user-controlled ID without authorization check
  const orderId = params.id;
  const order = await (global as any).db.orders.findUnique({ where: { id: orderId } });

  return NextResponse.json(order);
}
