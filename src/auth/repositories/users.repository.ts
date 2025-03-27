/*import { Repository, Entity, EntityRepository } from "typeorm";
import { UserEntity } from "./user.entity";
import { AuthCredentialsDto } from "./dto/auth.credentials.dto";

@EntityRepository(UserEntity)
export class UserRepository extends Repository<UserEntity> {
    async createUser(authCredentialsDto: AuthCredentialsDto): Promise<void> {
        const { username, password } = authCredentialsDto;
        const user = this.create({ username, password});
        await this.save(user);
    }
}*/

import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { AuthCredentialsDto } from '../dtos/auth.credentials.dto';
import { ConflictException, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

export class UsersRepository extends Repository<User> {
    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>
    ) {
        super(userRepository.target, userRepository.manager, userRepository.queryRunner);
    }

    async createUser(authCredentialsDto: AuthCredentialsDto): Promise<void> {
        const { email, password } = authCredentialsDto;

        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(password, salt);


        const user = this.create({ email, password: hashedPassword});
        try {
            await this.save(user);
        }catch (error){
            if (error.code === '23505') { // duplicate username
                throw new ConflictException('Username already exists');
            } else {
                throw new InternalServerErrorException();
            }
        }
        
        
    }

    async changePassword(userId,email: string, newPassword: string)
    {
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        const id = userId;
        //Find the user
        const userResult = await this.userRepository.findOne({
            where: { userId }
        });
        if (!userResult) {
        throw new NotFoundException('User not found...');
        }
        const user = this.create({ email, password: hashedPassword});

    }

    // sample method for demo purposes
    async findByEmail(email: string): Promise<User> {
        return await this.userRepository.findOne({
            where: { email }
     }); // could also be this.findOneBy({ email });, but depending on your IDE/TS settings, could warn that userRepository is not used though. Up to you to use either of the 2 methods
    }
    
    // your other custom methods in your repo...
}