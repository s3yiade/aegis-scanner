export interface Challenge {
  question: string;
  token: string;
}

export async function fetchChallenge(): Promise<Challenge | null> {
  try {
    const res = await fetch('/api/captcha');
    const data = await res.json();
    if (data.provider === 'self') return { question: data.question, token: data.token };
    return null;
  } catch {
    return null;
  }
}
