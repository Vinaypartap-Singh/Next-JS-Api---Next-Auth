import bcrypt from "bcryptjs";
import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import prisma from "./prisma";

export const authOptions: NextAuthOptions = {
    providers: [
        CredentialsProvider({
            name: "Credentails",
            credentials: {
                email: { label: "Email", type: "email" },
                password: { label: "Password", type: "password" }
            },
            async authorize(credentials) {

                if (!credentials?.email || !credentials?.password) {
                    throw new Error("Email and Password is required");
                }


                try {
                    const user = await prisma.user.findUnique({
                        where: {
                            email: credentials.email
                        }
                    })

                    if (!user) {
                        throw new Error("User Not Found");
                    }

                    const correctPassword = await bcrypt.compare(credentials.password, user.password);

                    if (!correctPassword) {
                        throw new Error("Incorrect Password");
                    }

                    return {
                        id: user.id.toString(),
                        email: user.email
                    }

                } catch (error) {
                    throw new Error(error as string);
                }
            }
        }),
    ],
    callbacks: {
        async jwt({ token, user }) {
            if (user) {
                token.id = user.id
            }
            return token
        },
        async session({ session, token }) {

            if (session?.user) {
                session.user.id = token.id as string
            }

            return session
        },
    },
    pages: {
        signIn: "/login",
        error: "/login"
    },

    session: {
        strategy: "jwt",
        maxAge: 30 * 24 * 60 * 60,
    },
    secret: process.env.NEXTAUTH_SECRET,
}