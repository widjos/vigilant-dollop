import { ForbiddenException, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from '@nestjs/config'
import { User, Bookmark, Prisma } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2'

@Injectable({})
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
        ) { }


    async signin(dto: AuthDto) {
        //find user by email
        const user = await this.prisma.user.findFirst({
            where: {
            email: dto.email,
            },
        });
        // if user doesnt exist throw exception
        if (!user) throw new ForbiddenException('Credentials incorrect');
        //compare passwords
        const pwMatches = await argon.verify(user.hash, dto.password);
        // if password incorrect throw exception
        if(!pwMatches) throw new ForbiddenException('Credentials incorrect');
        //send back user
        delete user.hash

        return this.signtoken(user.id, user.email)   
    }

    async signup(dto: AuthDto) {
        // generated the hash password
        const hash = await argon.hash(dto.password);
        //save the new user in the db
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash
                },
            });
            //return the saved user
            delete user.hash
            return user;
        } catch (error) {
            console.log("errr:" , error.code , typeof error)
            if (error instanceof Prisma.PrismaClientKnownRequestError) {
                console.log("Error code: ",error.code)
                if (error.code === 'P2002') {
                    
                    throw new ForbiddenException(
                        'Credentiala taken',
                    );
                }
            }
            throw error;
        }
    }

    async signtoken(userId:number, email:string): Promise<{access_token:string}>{
        const payload = {
            sub: userId,
            email
        }


        const secret = this.config.get('JWT_SECRET');
        const token =  await this.jwt.signAsync(
            payload, {
            expiresIn: '17m',
            secret: secret,
        });

        return {
            access_token: token
        }
    }

}