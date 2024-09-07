import { type Environments } from '@/enums/environment.enum';

declare global {
  namespace NodeJS {
    interface ProcessEnv {
      NODE_ENV: Environments;
      PORT: string;
      APP_BASE_URL: string;
      DATABASE_URL: string;
      ACCESS_TOKEN_SECRET: string;
      REFRESH_TOKEN_SECRET: string;
      ACCESS_TOKEN_EXPIRE: string;
      REFRESH_TOKEN_EXPIRE: string;
      EMAIL_USER: string;
      EMAIL_PASS: string;
      FRONTEND_URL: string;
      AUTO_VERIFY_EMAIL: 'true' | 'false';
      RESET_PASSWORD_TOKEN_EXPIRE: string;
      RESET_PASSWORD_TOKEN_SECRET: string;
      VERIFICATION_TOKEN_SECRET: string;
      ALLOW_AUTO_VERIFY: 'true' | 'false';
    }
  }
}

export {};
