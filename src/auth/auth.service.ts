/*mport { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { AuthCredentialsDto } from "./dto/auth.credentials.dto";
import { UserEntity } from "./user.entity";
import { Repository } from "typeorm";

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(UserEntity) private readonly repo: Repository<UserEntity>,
    ) {}

    async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
        this.repo.save(authCredentialsDto);
    }
}*/

import { Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import {  InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { UsersRepository } from './repositories/users.repository';
import { AuthCredentialsDto } from './dtos/auth.credentials.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './jwt-payload.interface';
import { AzureActiveDirectoryAccessTokenAuthentication } from 'typeorm/driver/sqlserver/authentication/AzureActiveDirectoryAccessTokenAuthentication';
import { RefreshTokenRepository } from './repositories/refresh-token.repository';
import { RefreshToken } from './entities/refresh-token.entity';
import { nanoid } from 'nanoid';
import { MailService } from 'src/services/mail.service';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersRepository: UsersRepository, // import as usual
        private readonly refreshTokenRepository: RefreshTokenRepository,
        private jwtService: JwtService,
        private mailService: MailService
    ) { }

    async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
        return this.usersRepository.createUser(authCredentialsDto);
    }

    async signIn(authCredentialsDto: AuthCredentialsDto): Promise<{ accessToken: string }> {
        const { email, password } = authCredentialsDto;
        const user = await this.usersRepository.findOne({
            where: { email }
        });

        if (user && (await bcrypt.compare(password, user.password))) {
            const accessToken: string= await this.generateUserTokens(email);
            return { accessToken };
        } else {
            throw new UnauthorizedException('Please check your login credentials');
        }
    }

    async refreshTokens(refreshToken: string) {
        const token:RefreshToken = await this.refreshTokenRepository.findByRefreshTokenValid(refreshToken);
    
        if (!token) {
          throw new UnauthorizedException('Refresh Token is invalid');
        }

        const user = await this.usersRepository.findOne({
            where: { id: token.userId }
        });

        if (!user) {
            throw new UnauthorizedException('Refresh Token is invalid');
          }

        return this.generateUserTokens(user.email);
      }

    async changePassword(email, oldPassword: string, newPassword: string) {
        const user = await this.usersRepository.findOne({
            where: { email }
        });

        if (!user) {
          throw new NotFoundException('User not found...');
        }
    
        //Compare the old password with the password in DB
        const passwordMatch = await bcrypt.compare(oldPassword, user.password);
        if (!passwordMatch) {
          throw new UnauthorizedException('Wrong credentials');
        }
    
        //Change user's password
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        await this.usersRepository.update({ id: user.id }, {
            password: hashedPassword,
          })

        return "User Updated Successfully";
      }


    async forgotPassword(email: string) {
        //Check that user exists
        const user = await this.usersRepository.findOne({
            where: { email }
        });

        if (user) {
            //If user exists, generate password reset link
            const expiryDate = new Date();
            expiryDate.setHours(expiryDate.getHours() + 1);

            const resetToken = nanoid(64);
            await this.refreshTokenRepository.create({
            token: resetToken,
            userId: user.id,
            expiryDate,
            });
            //Send the link to the user by email
            this.mailService.sendPasswordResetEmail(email, resetToken);
        }

        return { message: 'If this user exists, they will receive an email' };
    }

    async resetPassword(newPassword: string, resetToken: string) {
        //Find a valid reset token document
        const token = await this.refreshTokenRepository.findOneAndDelete({
          token: resetToken,
          expiryDate: { $gte: new Date() },
        });
    
        if (!token) {
          throw new UnauthorizedException('Invalid link');
        }
    
        //Change user password (MAKE SURE TO HASH!!)
        const user = await this.usersRepository.findOne({
            where: { id: token.userId }
        });
        
        if (!user) {
          throw new InternalServerErrorException();
        }
    
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
      }


    async generateUserTokens(email: string):Promise<string> {
        const payload: JwtPayload = { email };
        const accessToken: string = await this.jwtService.sign(payload);
        return  accessToken ;
    }
    

    /*findAll(): Promise<UserEntity[]> {
        return this.userRepository.find();
    }

    // call your repo method
    findOneByEmail(username: string): Promise<UserEntity> {
        return this.userRepository.findByEmail(username);
    }

    findOne(id: string): Promise<UserEntity> {
        return this.userRepository.findOneBy({ id });
    }

    async remove(id: string): Promise<void> {
        await this.userRepository.delete(id);
    }*/

    // your other custom methods in your service...
}