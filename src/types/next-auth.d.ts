// types/next-auth.d.ts
import NextAuth, { DefaultSession, DefaultUser } from 'next-auth';
import { JWT as NextAuthJWT } from 'next-auth/jwt';

declare module 'next-auth' {

  interface Session extends DefaultSession {
    user: {
      id: string;
      email: string;
      jwtToken: string;
      role: string;
      name: string;
    };
  }

  interface User extends DefaultUser {
    token: string;
  }
}

declare module 'next-auth/jwt' {
  interface JWT extends NextAuthJWT {
    userId: string;
    jwtToken: string;
  }
}
