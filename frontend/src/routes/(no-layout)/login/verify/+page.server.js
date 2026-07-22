/**
 * Magic Link Verification Page
 *
 * Handles the magic link callback:
 * 1. Extract token from URL query params (load — token is NOT consumed here)
 * 2. User clicks "Complete sign-in" → form action POSTs to backend to verify
 * 3. Set JWT cookies on success
 * 4. Redirect to /org
 *
 * Security: the token is only consumed by an explicit POST. GET requests
 * (link-preview bots, mail scanners, browser URL-bar prefetch) render the
 * confirmation page without burning the single-use token.
 */

import axios from 'axios';
import { redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import { env as publicEnv } from '$env/dynamic/public';

/** @type {import('@sveltejs/kit').ServerLoad} */
export async function load({ url }) {
  const token = url.searchParams.get('token');

  if (!token) {
    return { error: 'Missing verification token.' };
  }

  return { token };
}

/** @type {import('@sveltejs/kit').Actions} */
export const actions = {
  default: async ({ request, cookies }) => {
    const form = await request.formData();
    const token = form.get('token');

    if (!token) {
      return { error: 'Missing verification token.' };
    }

    try {
      const apiUrl = publicEnv.PUBLIC_DJANGO_API_URL;
      const response = await axios.post(
        `${apiUrl}/api/auth/magic-link/verify/`,
        { token },
        {
          headers: { 'Content-Type': 'application/json' },
          timeout: 10000
        }
      );

      const { access_token, refresh_token } = response.data;

      // Store JWT tokens in secure httpOnly cookies (same as Google OAuth flow)
      const secure = env.NODE_ENV === 'production';
      cookies.set('jwt_access', access_token, {
        path: '/',
        httpOnly: true,
        sameSite: 'lax',
        secure,
        maxAge: 60 * 60 * 24 // 1 day
      });
      cookies.set('jwt_refresh', refresh_token, {
        path: '/',
        httpOnly: true,
        sameSite: 'lax',
        secure,
        maxAge: 60 * 60 * 24 * 365 // 1 year
      });
    } catch (error) {
      const errorMessage = error.response?.data?.error || 'Verification failed';
      return { error: errorMessage };
    }

    // Success - redirect to org selection (same as Google OAuth)
    throw redirect(303, '/org');
  }
};
