import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getSupabaseAdmin } from '@/lib/supabase';
import { checkRateLimit, getClientIp } from '@/lib/ratelimit';
import { isSameOrigin } from '@/lib/originCheck';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const ResumeSchema = z.object({ email: z.string().trim().email().max(320) });

/**
 * Re-verification step after the report page's idle timeout clears its
 * in-memory/displayed state (see the useIdleTimeout hook on the report
 * page). The underlying scan/report data in the database is never
 * touched or deleted by idling — this just confirms the email matches an
 * existing lead for this scan before the client re-fetches and
 * re-displays it, as a lightweight check against someone else re-viewing
 * a report left idle on a shared screen without knowing the email that
 * originally unlocked it.
 */
export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Invalid request origin' }, { status: 403 });
  }

  const { id } = await params;
  const clientIp = getClientIp(req.headers);
  const rl = await checkRateLimit(clientIp);
  if (!rl.allowed) {
    return NextResponse.json({ error: 'Too many attempts' }, { status: 429 });
  }

  let body: z.infer<typeof ResumeSchema>;
  try {
    body = ResumeSchema.parse(await req.json());
  } catch {
    return NextResponse.json({ error: 'Invalid email' }, { status: 400 });
  }

  const supabase = getSupabaseAdmin();
  const { count } = await supabase
    .from('leads')
    .select('id', { count: 'exact', head: true })
    .eq('scan_id', id)
    .ilike('email', body.email);

  if (!count || count === 0) {
    return NextResponse.json({ error: 'That email doesn\'t match this report.' }, { status: 403 });
  }

  return NextResponse.json({ verified: true });
}
