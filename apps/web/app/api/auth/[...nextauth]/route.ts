import { NextAuthOptions } from 'next-auth'
import NextAuth from 'next-auth/next'
import EmailProvider from 'next-auth/providers/email'
import { PrismaAdapter } from '@next-auth/prisma-adapter'
import { prisma } from '@tip/db'

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    EmailProvider({
      server: {
        host: process.env.EMAIL_SERVER_HOST,
        port: process.env.EMAIL_SERVER_PORT,
        auth: {
          user: process.env.EMAIL_SERVER_USER,
          pass: process.env.EMAIL_SERVER_PASSWORD,
        },
      },
      from: process.env.EMAIL_FROM,
    }),
  ],
  pages: {
    signIn: '/signin',
    verifyRequest: '/verify-request',
  },
  callbacks: {
    async session({ session, user }) {
      if (session?.user && user) {
        session.user.id = user.id
        
        // Get user's organizations and roles
        const userOrgs = await prisma.userOrg.findMany({
          where: { userId: user.id },
          include: { org: true },
        })
        
        session.user.orgs = userOrgs.map(uo => ({
          id: uo.orgId,
          name: uo.org.name,
          role: uo.role,
        }))
      }
      return session
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
}

const handler = NextAuth(authOptions)

export { handler as GET, handler as POST }