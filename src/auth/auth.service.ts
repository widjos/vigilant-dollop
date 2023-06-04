import { Injectable } from "@nestjs/common";
import { User, Bookmark } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from  'argon2'

@Injectable({})
export class AuthService{
    constructor( private prisma: PrismaService){}


    signin(){
        return { msg: 'I singed in '}
    }

    async signup(dto: AuthDto){
        // generated the hash password
        const hash = await argon.hash(dto.password);
        //save the new user in the db
        const user = await this.prisma.user.create({
            data: {
                email: dto.email,
                hash
            },
        });
        //return the saved user
        delete user.hash
        return user;
    }

}