import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { UsersRepository } from './repositories/users.repository';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';
import { RefreshTokenRepository } from './repositories/refresh-token.repository';
import { MailService } from 'src/services/mail.service';
import { RefreshToken } from './entities/refresh-token.entity';
import { UtilsService } from './utils/utils-service';

@Module({
    /*imports: [TypeOrmModule.forFeature([UserEntity])],
    providers: [AuthService],
    controllers: [AuthController]*/
    imports: [
        PassportModule.register( {defaultStrategy: 'jwt'}),
        JwtModule.register({
            secret: 'topSecret51',
            signOptions: {
                expiresIn: 3600
            },
        }),
        TypeOrmModule.forFeature([User,RefreshToken])], // here we provide the TypeOrm support as usual, specifically for our UserEntity in this case
    providers: [AuthService, MailService, JwtStrategy,UsersRepository, RefreshTokenRepository, UtilsService], // here we provide our custom repo
    controllers: [AuthController],
    exports: [JwtStrategy, PassportModule]
    //exports: [AuthService, UsersRepository] // add this only if you use service and/or custom repo within another module/service
})
export class AuthModule {}
