export function captchaEnabled(env: Env): boolean {
  return Boolean(env.PRIVCAPTCHA_SECRET && env.PRIVCAPTCHA_SITEKEY);
}

export interface PrivCaptchaVerifyResult {
  success: boolean;
  challenge_ts?: string;
  hostname?: string;
  'error-codes'?: string[];
}

export async function verifyPrivCaptcha(
  secret: string,
  response: string,
  remoteIp?: string,
): Promise<PrivCaptchaVerifyResult> {
  if (!response) return { success: false, 'error-codes': ['missing-input-response'] };
  const body = new URLSearchParams({ secret, response });
  if (remoteIp) body.set('remoteip', remoteIp);
  try {
    const res = await fetch('https://privcaptcha.com/api/v1/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!res.ok) return { success: false, 'error-codes': ['verification-unavailable'] };
    return (await res.json()) as PrivCaptchaVerifyResult;
  } catch {
    return { success: false, 'error-codes': ['verification-unavailable'] };
  }
}
