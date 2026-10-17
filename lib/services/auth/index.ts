import { createSupabaseServerClient } from "@/lib/supabase/server";
import { createSupabaseServiceRoleClient } from "@/lib/supabase/service-role";
import type { UserType } from "@/types/domain";

export class AuthServiceError extends Error {}

export interface SignUpInput {
  email: string;
  password: string;
  userType: Extract<UserType, "client" | "expert">;
  // Client-specific
  companyName?: string;
  // Expert-specific
  fullName?: string;
}

/**
 * Two Supabase clients on purpose, each used for what only it can do:
 *
 *  - createSupabaseServerClient()    session-aware, anon key + cookies.
 *    Used ONLY for real Supabase Auth operations (signUp / signIn /
 *    signOut / getUser) — those read and write the auth cookies.
 *
 *  - createSupabaseServiceRoleClient()  bypasses RLS. Used for every
 *    table read/write. With RLS now enabled on every table
 *    (0006_enable_rls_everywhere.sql), the session client can't see
 *    application tables at all, and — critically for signup — there may
 *    be NO session yet: when "Confirm email" is on in Supabase (the
 *    default), signUp() returns a user but no session until they click
 *    the confirmation link. The old version of this function looked the
 *    new user's row up through the session client, which in that state
 *    sees nothing, and reported "profile row is missing" even though
 *    the trigger had created it.
 */
export async function signUp(input: SignUpInput) {
  const authClient = await createSupabaseServerClient();

  const appUrl = process.env.NEXT_PUBLIC_APP_URL;
  const { data, error } = await authClient.auth.signUp({
    email: input.email,
    password: input.password,
    options: {
      // Where the confirmation email's link sends the user. Must also be
      // listed under Supabase → Authentication → URL Configuration →
      // Redirect URLs, or Supabase silently falls back to the Site URL.
      emailRedirectTo: appUrl ? `${appUrl}/auth/callback` : undefined,
      // Captured as raw_user_meta_data — the 0002_auth_integration.sql
      // trigger reads this to set users.user_type at row-creation time.
      data: { user_type: input.userType },
    },
  });

  if (error) throw new AuthServiceError(error.message);
  if (!data.user) throw new AuthServiceError("Signup did not return a user");

  // Supabase deliberately does not error when the email is already
  // registered (to avoid leaking which emails have accounts) — it
  // returns a user object with an empty identities array instead.
  if (data.user.identities && data.user.identities.length === 0) {
    throw new AuthServiceError("An account with this email already exists. Try signing in instead.");
  }

  const db = createSupabaseServiceRoleClient();

  // The trigger has already created the public.users row by the time
  // signUp resolves (same transaction as the auth.users insert).
  const { data: appUser, error: lookupError } = await db
    .from("users")
    .select("id")
    .eq("auth_provider_id", data.user.id)
    .single();

  if (lookupError || !appUser) {
    throw new AuthServiceError(
      "Account created but the users row is missing — run database/migrations/0002_auth_integration.sql in the Supabase SQL editor."
    );
  }

  // upsert (not insert) so a retry after a partial failure doesn't die
  // on the unique(user_id) constraint.
  if (input.userType === "client") {
    const { error: profileError } = await db
      .from("client_profiles")
      .upsert(
        { user_id: appUser.id, company_name: input.companyName ?? "Unnamed company" },
        { onConflict: "user_id", ignoreDuplicates: true }
      );
    if (profileError) throw new AuthServiceError(profileError.message);
  } else {
    const { error: profileError } = await db
      .from("expert_profiles")
      .upsert(
        { user_id: appUser.id, headline: input.fullName ?? "New expert" },
        { onConflict: "user_id", ignoreDuplicates: true }
      );
    if (profileError) throw new AuthServiceError(profileError.message);
  }

  return {
    userId: appUser.id as string,
    authUserId: data.user.id,
    // No session means Supabase is waiting for the user to click the
    // confirmation link — the UI must say so, not redirect to a
    // dashboard that will bounce them straight back to /login.
    needsEmailConfirmation: !data.session,
  };
}

export async function signIn(email: string, password: string) {
  const supabase = await createSupabaseServerClient();
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) {
    // Supabase's message for an unconfirmed address is "Email not
    // confirmed" — pass that through clearly since it's actionable.
    throw new AuthServiceError(error.message);
  }
  return data;
}

export async function signOut() {
  const supabase = await createSupabaseServerClient();
  const { error } = await supabase.auth.signOut();
  if (error) throw new AuthServiceError(error.message);
}

/**
 * Resolves the currently authenticated Supabase session into our
 * application-level user row. Returns null if no one is signed in or
 * the account is suspended/deleted — callers (Server Components,
 * layouts) decide what to do with that (usually redirect to /login).
 *
 * Identity comes from the session client (auth.getUser() verifies the
 * JWT with Supabase, it isn't just decoding a cookie); the row lookup
 * itself goes through the service-role client since RLS is deny-by-
 * default on `users` for anyone but the row's owner, and we've already
 * established who the caller is.
 */
export async function getCurrentAppUser() {
  const supabase = await createSupabaseServerClient();
  const { data: { user: authUser } } = await supabase.auth.getUser();
  if (!authUser) return null;

  const db = createSupabaseServiceRoleClient();
  const { data: appUser } = await db
    .from("users")
    .select("id, email, user_type, status")
    .eq("auth_provider_id", authUser.id)
    .single();

  if (!appUser || appUser.status !== "active") return null;

  return appUser;
}
