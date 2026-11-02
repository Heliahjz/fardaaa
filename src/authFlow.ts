import { NavItem } from './components/Sidebar';

export type AuthState = 'unknown' | 'unauthenticated' | 'pending' | 'authenticated';

/**
 * Determines the target view after admin login.
 * If initial setup is pending, routes directly to the 'account' setup view.
 * Otherwise, routes to 'dashboard'.
 */
export function viewAfterLogin(data: any): NavItem {
  const isPending =
    data?.isInitialPending === true ||
    data?.profile?.initialSetupCompleted === false ||
    data?.initialSetupCompleted === false;

  return isPending ? 'account' : 'dashboard';
}

/**
 * Enforces that admin data (orders, messages, stats, bot config) is NEVER
 * fetched when initial setup is pending, user is unauthenticated, or auth state is unknown.
 */
export function shouldFetchAdminData(
  isPending: boolean | null,
  isAuthenticated: boolean,
  authState?: AuthState
): boolean {
  if (authState === 'unknown' || !isAuthenticated || isPending === true || isPending === null) {
    return false;
  }
  return true;
}

export interface SetupSuccessResult {
  targetTab: NavItem;
  successMessage: string;
  shouldLogout: boolean;
}

/**
 * Handles post-setup transition:
 * Informs the caller to invalidate tokens, clear cached state, and route to login.
 */
export function handleSetupSuccess(): SetupSuccessResult {
  return {
    targetTab: 'dashboard',
    successMessage:
      'راه‌اندازی با موفقیت انجام شد. تمامی نشست‌های قبلی باطل شدند. لطفاً با نام کاربری و رمز عبور دائمی جدید وارد شوید.',
    shouldLogout: true,
  };
}

export interface UsernameValidationResult {
  isValid: boolean;
  code?: string;
  error?: string;
}

/**
 * Shared client-side validation mirroring the server's isValidAdminUsername rules.
 */
export function isValidAdminUsernameClient(
  username: string,
  isPending: boolean,
  initialUsername = 'onival_setup'
): UsernameValidationResult {
  const u = (username || '').trim();
  if (!/^[a-zA-Z0-9._-]{3,32}$/.test(u)) {
    return {
      isValid: false,
      code: 'INVALID_USERNAME',
      error: 'نام کاربری جدید باید بین ۳ تا ۳۲ کاراکتر و فقط شامل حروف انگلیسی، اعداد، نقطه، خط فاصله یا زیرخط باشد.',
    };
  }
  if (u.includes('@')) {
    return {
      isValid: false,
      code: 'INVALID_USERNAME',
      error: 'نام کاربری نمی‌تواند ساختار ایمیل داشته باشد.',
    };
  }
  if (isPending && u.toLowerCase() === initialUsername.toLowerCase()) {
    return {
      isValid: false,
      code: 'USERNAME_SAME_AS_INITIAL',
      error: 'نام کاربری جدید باید با شناسه کاربری موقت اولیه متفاوت باشد.',
    };
  }
  if (u.toLowerCase() === 'admin') {
    return {
      isValid: false,
      code: 'USERNAME_RESERVED',
      error: 'استفاده از نام کاربری عمومی admin مجاز نمی‌باشد.',
    };
  }
  return { isValid: true };
}

/**
 * Determines the initial value for the username field.
 * In pending setup state, it MUST start empty ('').
 * In completed state, it can be populated with the existing username.
 */
export function getInitialUsernameForState(
  isPending: boolean,
  profileUsername?: string
): string {
  if (isPending) {
    return '';
  }
  return profileUsername || 'admin';
}

