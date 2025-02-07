import prisma from "@/lib/prisma";
import bcrypt from "bcryptjs";
import { NextRequest, NextResponse } from "next/server";


export async function POST(req: NextRequest, res: NextResponse) {
    try {

        const body = await req.json();

        if (!body || typeof body !== "object") {
            return NextResponse.json({
                message: "Invalid request payload",
                status: 400
            });
        }


        const { email, password } = body;

        if (!email || !password) {
            return NextResponse.json({
                message: "Email and Password is required",
                status: 400
            });
        }

        const exisingUser = await prisma.user.findUnique({
            where: {
                email
            }
        });


        if (exisingUser) {
            return NextResponse.json({
                message: "User Already Exist. Please Use Another Email.",
                status: 400
            });
        }


        // Encrypt Password

        const salt = bcrypt.genSaltSync(12);
        const hashedPassword = bcrypt.hashSync(password, salt);

        await prisma.user.create({
            data: {
                email,
                password: hashedPassword
            }
        })


        return NextResponse.json({
            message: "Account Created Successufully",
            status: 201
        })


    } catch (error) {
        console.error(error);
        return NextResponse.error();
    }
}