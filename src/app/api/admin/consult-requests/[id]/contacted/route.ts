import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { verifyAdminSession, ADMIN_SESSION_COOKIE } from '@/lib/adminAuth';
import { getSupabaseAdmin } from '@/lib/supabase';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const BodySchema = z.object({ contacted: z.boolean() });

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const session = req.cookies.get(ADMIN_SESSION_COOKIE)?.value;
  if (!verifyAdminSession(session)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;

  let body: z.infer<typeof BodySchema>;
  try {
    body = BodySchema.parse(await req.json());
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
  }

  const supabase = getSupabaseAdmin();
  const { error } = await supabase.from('consult_requests').update({ contacted: body.contacted }).eq('id', id);

  if (error) {
    return NextResponse.json({ error: 'Failed to update' }, { status: 500 });
  }

  return NextResponse.json({ ok: true });
}
