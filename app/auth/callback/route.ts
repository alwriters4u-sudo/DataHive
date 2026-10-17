import { NextResponse, type NextRequest } from "next/server";
import type { EmailOtpType } from "@supabase/supabase-js";
import { createSupabaseServerClient } from "@/lib/supabase/server";
import { getCurrentAppUser } from "@/lib/services/auth";

/**
 * Landing point for the link in Supabase's confirmation email. This route
 * did not exist before — the email's link had nowhere to go, which is why
 * "email verification failed" kept happening even with correct Supabase
 * URL settings. Supports both link styles Supabase can send:
 *   ?code=...                      (PKCE flow, the @supabase/ssr default)
 *   ?token_hash=...&type=signup    (OTP-style email templates)
 */
export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const tokenHash = searchParams.get("token_hash");
  const type = searchParams.get("type") as EmailOtpType | null;

  const supabase = await createSupabaseServerClient();
  let verified = false;

  if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    verified = !error;
  } else if (tokenHash && type) {
    const { error } = await supabase.auth.verifyOtp({ type, token_hash: tokenHash });
    verified = !error;
  }

  if (!verified) {
    return NextResponse.redirect(`${origin}/login?error=verify_failed`);
  }

  const appUser = await getCurrentAppUser();
  const destination =
    appUser?.user_type === "expert" ? "/expert/dashboard" :
    appUser?.user_type === "admin" ? "/admin/dashboard" :
    "/client/dashboard";
  return NextResponse.redirect(`${origin}${destination}`);
}
