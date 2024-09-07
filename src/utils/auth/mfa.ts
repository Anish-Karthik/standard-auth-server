import speakeasy from 'speakeasy';
import qrcode from 'qrcode';

interface MFATokenData {
  email: string;
  mfaSecret: string;
}

export const generateMFASecret = (user: { email: string }) => {
  const secret = speakeasy.generateSecret({
    name: 'YourApp (' + user.email + ')',
  });

  const qrCodeDataURL = secret.otpauth_url
    ? qrcode.toDataURL(secret.otpauth_url)
    : undefined;

  if (!qrCodeDataURL) {
    throw new Error('Failed to generate QR code data URL.');
  }

  return { secret: secret.base32, qrCodeDataURL };
};

export const verifyMFAToken = (user: MFATokenData, token: string) => {
  return speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token,
    window: 1,
  });
};
