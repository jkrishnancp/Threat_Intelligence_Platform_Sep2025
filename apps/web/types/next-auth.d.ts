import NextAuth from "next-auth"

declare module "next-auth" {
  interface Session {
    user: {
      id: string
      email: string
      name?: string
      image?: string
      orgs?: {
        id: string
        name: string
        role: string
      }[]
    }
  }
}