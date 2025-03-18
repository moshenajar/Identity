import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user.entity';
import { UsersRepository } from './users.repository';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';

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
        TypeOrmModule.forFeature([User])], // here we provide the TypeOrm support as usual, specifically for our UserEntity in this case
    providers: [AuthService, JwtStrategy,UsersRepository], // here we provide our custom repo
    controllers: [AuthController],
    exports: [JwtStrategy, PassportModule]
    //exports: [AuthService, UsersRepository] // add this only if you use service and/or custom repo within another module/service
})
export class AuthModule {}
