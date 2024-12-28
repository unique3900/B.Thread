

import prisma from '@/db';
import db from '@/db';
import CredentialsProvider from 'next-auth/providers/credentials';
import bcrypt from 'bcrypt';
import { JWT } from 'next-auth/jwt';
import { JWTPayload, SignJWT, importJWK } from 'jose';
import { randomUUID } from 'crypto';
import { NextAuthOptions, Session } from 'next-auth';

export interface ISession extends Session {
  user: {
    id: string;
    email: string;
    jwtToken: string;
    role: string;
    name: string;
  };
}

interface Token extends JWT {
  userId: string;
  jwtToken: string;
}

interface User {
  id: string;
  name: string;
  email: string;
  token: string;
}

const generateJWT = async (payload: JWTPayload) => {
  const secret = process.env.JWT_SECRET || 'secret';
  const jwk = await importJWK({ k: secret, alg: 'HS256', kty: 'oct' });

  const jwt = await new SignJWT({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
  })
    .setProtectedHeader({
      alg: 'HS256',
    })
    .setExpirationTime('24h')
    .sign(jwk);
  return jwt;
};

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: 'credentials',
      credentials: {
        userName: { label: 'username', type: 'text', placeholder: 'username' },
        password: { label: 'password', type: 'password', placeholder: 'password' },
      },
      async authorize(credentials: Record<'userName' | 'password', string> | undefined) {
        if (!credentials) return null;

        try {
          const hashedPassword = await bcrypt.hash(credentials.password, 10);
          const userExist = await prisma.user.findFirst({
            where: { email: credentials.userName },
            select: { email: true, password: true, id: true, name: true, token: true },
          });

          if (userExist && userExist.password && (await bcrypt.compare(credentials.password, userExist.password))) {
            const jwt = await generateJWT({ email: userExist.email, id: userExist.id });
            await db.user.update({
              where: { id: userExist.id },
              data: { token: jwt },
            });

            return {
              id: userExist.id,
              name: userExist.name || 'Unnamed User',
              email: userExist.email,
              token: jwt,
            } as unknown as User;
          } else {
            const newUser = await db.user.create({
              data: {
                email: credentials.userName,
                password: hashedPassword,
                token: await generateJWT({ email: credentials.userName }),
              },
            });

            return {
              id: newUser.id,
              name: newUser.name || 'Unnamed User',
              email: newUser.email,
              token: newUser.token,
            } as unknown as User;
          }
        } catch (error) {
          console.error('Authorize Error:', error);
          return null;
        }
      },
    }),
  ],
  secret: process.env.JWT_SECRET || 'secret',
  callbacks: {
    session: async ({ session, token }) => {
      const updatedSession: ISession = session as ISession;
      if (updatedSession.user && (token as Token).userId) {
        updatedSession.user.id = (token as Token).userId;
        updatedSession.user.jwtToken = (token as Token).jwtToken;
        updatedSession.user.role = 'user'; 
      }
      return updatedSession;
    },
    jwt: async ({ token, user }) => {
      if (user) {
        token = {
          ...token,
          userId: (user as User).id,
          jwtToken: (user as User).token,
        };
      }
      return token;
    },
  },
 
};
