'use server';

import prisma from "@/lib/prisma";
import bcrypt from "bcryptjs";

export async function RegsiterUser(email: string, password: string) {
    try {
        const existingUser = await prisma.user.findUnique({
            where: {
                email
            }
        });

        if (existingUser) {
            return {
                message: "User Already Exist. Please Use Another Email.",
                status: 400
            }
        }


        const salt = bcrypt.genSaltSync(12);

        const hashedPassword = bcrypt.hashSync(password, salt);

        await prisma.user.create({
            data: {
                email,
                password: hashedPassword
            }
        })

        return {
            message: "Account Created Successufully",
            status: 201
        }


    } catch (error) {
        console.error(error);
    }
}