import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../entities/user.entity';
import { ConflictException, InternalServerErrorException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { RefreshToken } from '../entities/refresh-token.entity';
import { MoreThan, MoreThanOrEqual, LessThan, LessThanOrEqual,Repository, Raw  } from "typeorm";
import { format } from "date-fns";

export const MoreThanDate = (date: Date) => MoreThan(format(date, 'YYYY-MM-DD HH:MM:SS'))
export const LessThanDate = (date: Date) => LessThan(format(date, 'YYYY-MM-DD HH:MM:SS'))

export class RefreshTokenRepository extends Repository<RefreshToken> {
    constructor(
        @InjectRepository(RefreshToken)
        private refreshTokenRepository: Repository<RefreshToken>
    ) {
        super(refreshTokenRepository.target, refreshTokenRepository.manager, refreshTokenRepository.queryRunner);
    }

    async findByRefreshToken(token: string): Promise<RefreshToken> {
        return await this.refreshTokenRepository.findOne({
            where: { token }
     }); 
    }


    async findByRefreshTokenValid(refreshToken: string): Promise<RefreshToken> {
            return await this.refreshTokenRepository.findOne({
            where: [{ token: refreshToken}, {expiryDate: Raw((alias) => `${alias} > NOW()`) }]
        });
    }

    async DeteteRefreshToken(){
        return await this.refreshTokenRepository.createQueryBuilder()
        .delete()
    .from(RefreshToken)
    .where("id = :id", { id: 1 })
    .execute()
    }

    
}