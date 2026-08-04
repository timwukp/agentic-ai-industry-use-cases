import { Amplify } from 'aws-amplify'
import {
  confirmSignIn,
  fetchAuthSession,
  getCurrentUser,
  signIn,
  signOut,
  type SignInOutput,
} from 'aws-amplify/auth'
import { config } from './config'

export function configureAmplify(): void {
  Amplify.configure({
    Auth: {
      Cognito: {
        userPoolId: config.userPoolId,
        userPoolClientId: config.userPoolClientId,
      },
    },
  })
}

export interface AuthUser {
  username: string
  /** Cognito sub — used as the AgentCore actorId. */
  sub: string
  email?: string
}

export type SignInChallenge = 'TOTP' | 'NEW_PASSWORD' | 'DONE' | 'UNSUPPORTED'

function mapNextStep(output: SignInOutput): SignInChallenge {
  switch (output.nextStep.signInStep) {
    case 'DONE':
      return 'DONE'
    case 'CONFIRM_SIGN_IN_WITH_TOTP_CODE':
      return 'TOTP'
    case 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED':
      return 'NEW_PASSWORD'
    default:
      return 'UNSUPPORTED'
  }
}

export async function startSignIn(
  username: string,
  password: string,
): Promise<SignInChallenge> {
  const output = await signIn({ username, password })
  return mapNextStep(output)
}

/** Answers the pending challenge (TOTP code or new password). */
export async function answerChallenge(response: string): Promise<SignInChallenge> {
  const output = await confirmSignIn({ challengeResponse: response })
  return mapNextStep(output)
}

/** Returns the current Cognito ACCESS token, or null when signed out. */
export async function getAccessToken(): Promise<string | null> {
  try {
    const session = await fetchAuthSession()
    return session.tokens?.accessToken?.toString() ?? null
  } catch {
    return null
  }
}

/** Loads the signed-in user, or null when no valid session exists. */
export async function loadCurrentUser(): Promise<AuthUser | null> {
  try {
    const [user, session] = await Promise.all([getCurrentUser(), fetchAuthSession()])
    if (!session.tokens?.accessToken) return null
    const payload = session.tokens.accessToken.payload
    return {
      username: user.username,
      sub: (payload.sub as string | undefined) ?? user.userId,
      email:
        typeof payload.email === 'string'
          ? payload.email
          : (user.signInDetails?.loginId ?? undefined),
    }
  } catch {
    return null
  }
}

export async function doSignOut(): Promise<void> {
  await signOut()
}
