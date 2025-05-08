import { InjectRepository } from '@nestjs/typeorm';
import { RefreshToken } from '../entities/refresh-token.entity';
import { MoreThan, LessThan, Repository, Raw } from "typeorm";
import { format } from "date-fns";
import { DeleteRefreshTokenDto } from '../dtos/detete-refresh-token.dto';

export const MoreThanDate = (date: Date) => MoreThan(format(date, 'YYYY-MM-DD HH:MM:SS'))
export const LessThanDate = (date: Date) => LessThan(format(date, 'YYYY-MM-DD HH:MM:SS'))

export class RefreshTokenRepository extends Repository<RefreshToken> {
    constructor(
        @InjectRepository(RefreshToken)
        private refreshTokenRepository: Repository<RefreshToken>
    ) {
        super(refreshTokenRepository.target, refreshTokenRepository.manager, refreshTokenRepository.queryRunner);
    }

    async findByRefreshToken(refreshToken: string): Promise<RefreshToken | null> {
        return this.refreshTokenRepository.findOne({
            where: {
                refreshToken: refreshToken,
                expiryDate: MoreThan(new Date())
            }
        });
    }
    

    async findByRefreshToken1(refreshToken: string): Promise<RefreshToken> {
        return await this.refreshTokenRepository.findOne({
            where: { refreshToken }
        });
    }


    async findByRefreshTokenValid(refreshToken: string): Promise<RefreshToken> {
        return await this.refreshTokenRepository.findOne({
            where: [{ refreshToken: refreshToken }, { expiryDate: Raw((alias) => `${alias} > NOW()`) }]
        });
    }

    /*async findById(id: string): Promise<User | null> {
        return this.userRepository
          .createQueryBuilder('user')
          .where('user.id = :id', { id })
          .getOne();
      }*/
      
    
}