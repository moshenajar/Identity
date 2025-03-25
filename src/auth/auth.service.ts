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

import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { UsersRepository } from './users.repository';
import { AuthCredentialsDto } from './dto/auth.credentials.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './jwt-payload.interface';
import { AzureActiveDirectoryAccessTokenAuthentication } from 'typeorm/driver/sqlserver/authentication/AzureActiveDirectoryAccessTokenAuthentication';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersRepository: UsersRepository, // import as usual
        private jwtService: JwtService,
    ) { }

    async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
        return this.usersRepository.createUser(authCredentialsDto);
    }

    async signIn(authCredentialsDto: AuthCredentialsDto): Promise<{ accessToken: string }> {
        const { username, password } = authCredentialsDto;
        const user = await this.usersRepository.findOne({
            where: { username }
     });

        if (user && (await bcrypt.compare(password, user.password))) {
            const payload: JwtPayload = { username };
            const accessToken: string = await this.jwtService.sign(payload);
            return { accessToken };
        } else {
            throw new UnauthorizedException('Please check your login credentials');
        }
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