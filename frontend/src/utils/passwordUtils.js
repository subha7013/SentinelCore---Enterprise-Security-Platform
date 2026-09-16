/**
 * Password validation rules and generation utilities for SentinelCore
 */

export const PASSWORD_RULES = [
  { id: 'length', label: 'At least 8 characters', test: (p) => p.length >= 8 },
  { id: 'uppercase', label: 'At least 1 uppercase letter (A-Z)', test: (p) => /[A-Z]/.test(p) },
  { id: 'lowercase', label: 'At least 1 lowercase letter (a-z)', test: (p) => /[a-z]/.test(p) },
  { id: 'number', label: 'At least 1 number (0-9)', test: (p) => /[0-9]/.test(p) },
  { id: 'special', label: 'At least 1 special char (@, #, $, !, %, etc.)', test: (p) => /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(p) },
];

export function getPasswordRulesStatus(password = '') {
  return PASSWORD_RULES.map((rule) => ({
    ...rule,
    passed: rule.test(password),
  }));
}

export function isPasswordStrong(password = '') {
  return PASSWORD_RULES.every((rule) => rule.test(password));
}

export function evaluatePasswordStrength(password = '') {
  if (!password) {
    return { score: 0, label: 'Empty', color: 'bg-slate-700', isStrong: false };
  }

  const rulesStatus = getPasswordRulesStatus(password);
  const passedCount = rulesStatus.filter((r) => r.passed).length;
  
  // Additional length bonus
  let bonus = 0;
  if (password.length >= 12) bonus += 1;

  const totalPoints = passedCount + bonus; // 0 - 6 scale

  if (totalPoints <= 2) {
    return { score: 25, label: 'Weak', color: 'bg-red-500', textClass: 'text-red-400', isStrong: false };
  } else if (totalPoints <= 4) {
    return { score: 60, label: 'Medium', color: 'bg-amber-500', textClass: 'text-amber-400', isStrong: false };
  } else if (passedCount === 5) {
    return { score: 100, label: 'Strong', color: 'bg-emerald-500', textClass: 'text-emerald-400', isStrong: true };
  } else {
    return { score: 75, label: 'Good', color: 'bg-sky-500', textClass: 'text-sky-400', isStrong: false };
  }
}

export function generateStrongPassword() {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const numbers = '23456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  const getRandomChar = (charset) => {
    const cryptoObj = window.crypto || window.msCrypto;
    if (cryptoObj) {
      const array = new Uint32Array(1);
      cryptoObj.getRandomValues(array);
      return charset[array[0] % charset.length];
    }
    return charset[Math.floor(Math.random() * charset.length)];
  };

  // Ensure minimum requirement coverage
  const requiredChars = [
    getRandomChar(upper),
    getRandomChar(upper),
    getRandomChar(lower),
    getRandomChar(lower),
    getRandomChar(numbers),
    getRandomChar(numbers),
    getRandomChar(symbols),
    getRandomChar(symbols),
  ];

  const allChars = upper + lower + numbers + symbols;
  const targetLength = 14;

  while (requiredChars.length < targetLength) {
    requiredChars.push(getRandomChar(allChars));
  }

  // Fisher-Yates shuffle
  for (let i = requiredChars.length - 1; i > 0; i--) {
    const cryptoObj = window.crypto || window.msCrypto;
    let j;
    if (cryptoObj) {
      const array = new Uint32Array(1);
      cryptoObj.getRandomValues(array);
      j = array[0] % (i + 1);
    } else {
      j = Math.floor(Math.random() * (i + 1));
    }
    [requiredChars[i], requiredChars[j]] = [requiredChars[j], requiredChars[i]];
  }

  return requiredChars.join('');
}
