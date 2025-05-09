import { HttpStatus, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { User } from './entities/user.entity';
import { UsersRepository } from './repositories/users.repository';
import { AuthCredentialsDto } from './dtos/auth.credentials.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { RefreshTokenRepository } from './repositories/refresh-token.repository';
import { MailService } from 'src/services/mail.service';
import { LoginDto } from './dtos/login.dto';
import { nanoid } from 'nanoid';
import { UtilsService } from './utils/utils-service';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ForgotPasswordOtpDto } from './dtos/forgot-password-otp.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { Token } from './model/token';
import { RefreshToken } from './entities/refresh-token.entity';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersRepository: UsersRepository, // import as usual
        private readonly refreshTokenRepository: RefreshTokenRepository,
        private jwtService: JwtService,
        private mailService: MailService,
        private utilsService: UtilsService,
    ) { }

    async signUp(authCredentialsDto: AuthCredentialsDto) {
        const { username, password } = authCredentialsDto;
        const user = await this.usersRepository.findOne({
            where: { username }
        });

        if (user === null) {
            this.usersRepository.createUser(authCredentialsDto);

            return this.utilsService.apiResponse(
                HttpStatus.OK,
                null,
                [{ message: "The user is created.", property: "signUp" }]
            );
        }


        return this.utilsService.apiResponse(
            HttpStatus.NOT_FOUND,
            null,
            [{ message: "Please enter a different username.", property: "signUp" }]
        );
    }

    async login(loginDto: LoginDto) {
        const { username, password } = loginDto;
        const user = await this.usersRepository.findOne({
            where: { username }
        });

        if (user && (await this.comparePasswords(password, user.password))) {
            //Token and Refresh Token Revocation
            const expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() - 1);
            await this.refreshTokenRepository
                .createQueryBuilder()
                .update(RefreshToken)
                .set({ expiryDate: expiryDate })
                .where('userId = :userId', { userId: user.userId })
                .execute();
            //Generate JWT tokens
            const token = await this.generateUserTokens(user.userId);
            
            return this.utilsService.apiResponse<Token>(
                HttpStatus.OK,
                token,
                [{ message: "", property: "login" }]
            );
        } else {
            return this.utilsService.apiResponse(
                HttpStatus.NOT_FOUND,
                null,
                [{ message: "The username or password is incorrect.", property: "login" }]
            );
        }
    }

    async refreshToken(user: User) {
        if (!user) {
            return this.utilsService.apiResponse(
                HttpStatus.NOT_FOUND,
                null,
                [{ message: "Wrong credentials.", property: "refreshToken" }]
            );
        }

        const token: Token = await this.generateUserTokens(user.userId);

        if (token)
            return this.utilsService.apiResponse(
                HttpStatus.CREATED,
                token,
                [{ message: "The token is created", property: "refreshToken" }]
            );


        return this.utilsService.apiResponse(
            HttpStatus.NOT_FOUND,
            null,
            [{ message: "Wrong credentials.", property: "refreshToken" }]
        );
    }

    async changePassword(userId, oldPassword: string, newPassword: string) {
        const user = await this.usersRepository.findOne({
            where: { userId }
        });

        if (!user) {
            return this.utilsService.apiResponse(
                HttpStatus.NOT_FOUND,
                null,
                [{ message: "Wrong credentials.", property: "changePassword" }]
            );
        }

        //Compare the old password with the password in DB
        const passwordMatch = await bcrypt.compare(oldPassword, user.password);
        if (!passwordMatch) {
            return this.utilsService.apiResponse(
                HttpStatus.NOT_FOUND,
                null,
                [{ message: "Wrong credentials.", property: "changePassword" }]
            );
        }

        //Change user's password
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        await this.usersRepository.update({ userId: user.userId }, {
            password: hashedPassword,
        })

        return this.utilsService.apiResponse(
            HttpStatus.OK,
            null,
            [{ message: "Password updated successfully.", property: "changePassword" }]
        );
    }

    async forgotPasswordOtp(forgotPasswordOtpDto: ForgotPasswordOtpDto) {

    }

    async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {

        if (forgotPasswordDto.otp != forgotPasswordDto.originalOtp)
            throw new NotFoundException('Otp not found...');


        let userId = forgotPasswordDto.userId;
        //Check that user exists
        const user = await this.usersRepository.findOne({
            where: { userId }
        });

        if (!user) {
            throw new NotFoundException('User not found...');
        }


        //If user exists, generate password reset link
        const expiryDate = new Date();
        expiryDate.setHours(expiryDate.getHours() + 1);

        const resetToken = nanoid(64);
        await this.refreshTokenRepository.create({
            refreshToken: resetToken,
            userId: user.userId,
            expiryDate,
        });
        //Send the link to the user by email
        this.mailService.sendPasswordResetEmail(user.username, resetToken);


        return { message: 'If this user exists, they will receive an email' };
    }

    async resetPassword(resetPasswordDto: ResetPasswordDto) {
        //Find a valid reset token document
        const token = await this.refreshTokenRepository.findOneBy({
            refreshToken: resetPasswordDto.resetToken,
            expiryDate: new Date()
        })

        if (!token) {
            throw new UnauthorizedException('Invalid link');
        }

        await this.refreshTokenRepository.remove(token);

        //Change user password (MAKE SURE TO HASH!!)
        const user = await this.usersRepository.findOneBy({
            userId: token.userId
        });

        if (!user) {
            throw new InternalServerErrorException();
        }

        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(resetPasswordDto.newPassword, salt);

        user.password = hashedPassword;

        await this.usersRepository.save(user);

    }


    async storeRefreshToken(refreshToken: string, userId: string) {
        // Calculate expiry date 3 days from now
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 3);

        const refreshTokenRow = await this.refreshTokenRepository.findOneBy({
            refreshToken: refreshToken
        })

        if (refreshTokenRow) {
            refreshTokenRow.expiryDate = expiryDate;
            //TODO - dosnt save refresh token
            await this.refreshTokenRepository.save(refreshTokenRow);
            return;

        }


        const refreshTokenObj = this.refreshTokenRepository.create({
            refreshToken: refreshToken,
            userId: userId,
            expiryDate: expiryDate,
        });

        await this.refreshTokenRepository.save(refreshTokenObj);

        return;
    }

    async validateToken(accessToken: string) {
        let userId: string = null;
        if (!accessToken) {
            throw new UnauthorizedException('Invalid token');
        }

        try {
            const payload = this.jwtService.verify(accessToken);
            userId = payload.userId;
            const user = await this.usersRepository.findOneBy({
                userId: userId
            });

            return this.utilsService.apiResponse<User>(
                HttpStatus.OK,
                user,
                [{ message: "The token is valid", property: "validateToken" }]
            );
        }
        catch (e) {
            return this.utilsService.apiResponse(
                HttpStatus.UNAUTHORIZED,
                null,
                [{ message: "Invalid Token", property: "validateToken" }]
            );
        }
    }

    async validateRefreshToken(jwtRefreshToken: string) {
        let userId: string = null;
        if (!jwtRefreshToken) {
            return this.utilsService.apiResponse(
                HttpStatus.UNAUTHORIZED,
                null,
                [{ message: "Invalid Refresh Token", property: "validateRefreshToken" }]
            );
        }

        try {
            const payload = this.jwtService.verify(jwtRefreshToken);
            userId = payload.userId;
            const user = await this.usersRepository.findOneBy({
                userId: userId
            });
            const dbRefreshTokenRow = await this.refreshTokenRepository.findByRefreshToken(jwtRefreshToken);
            if (dbRefreshTokenRow) {
                const expiryDate = new Date();
                expiryDate.setDate(expiryDate.getDate() - 1);
                dbRefreshTokenRow.expiryDate = expiryDate;
                await this.refreshTokenRepository.save(dbRefreshTokenRow);

                return this.utilsService.apiResponse<User>(
                    HttpStatus.OK,
                    user,
                    [{ message: "The token is valid", property: "validateRefreshToken" }]
                );
            }

            return this.utilsService.apiResponse(
                HttpStatus.UNAUTHORIZED,
                null,
                [{ message: "Invalid Refresh Token", property: "validateRefreshToken" }]
            );
        }
        catch (e) {
            return this.utilsService.apiResponse(
                HttpStatus.UNAUTHORIZED,
                null,
                [{ message: "Invalid Refresh Token", property: "validateRefreshToken" }]
            );
        }
    }



    async comparePasswords(plainPassword: string, hashedPassword: string): Promise<boolean> {
        return await bcrypt.compare(plainPassword, hashedPassword);
    }


    getUserByUserId(userId: string) {
        const user: User = {
            userId: '1',
            username: 'John Doe',
            password: 'john.doe@example.com',
        };

        return this.utilsService.apiResponse(
            HttpStatus.OK,
            { user: user },
            [{ message: "The user is valid", property: "getUserByUserId" }]
        );

    }



    async generateUserTokens(userId) {
        const accessToken = await this.generateToken1hSign({ userId });
        const refreshToken = await this.generateToken7dSign({ userId });
        await this.storeRefreshToken(refreshToken, userId);

        return {
            accessToken: accessToken,
            refreshToken: refreshToken,
            userId: userId
        };

    }

    async generateToken7dSign(payload: object) {
        return this.jwtService.sign(payload, {
            expiresIn: '7d', // Override default expiration
            //expiresIn: '5m', // Override default expiration
            algorithm: 'HS512', // Use a different algorithm
            audience: 'your-app',
            issuer: 'your-company',
        });
    }

    async generateToken1hSign(payload: object) {
        return this.jwtService.sign(payload, {
            expiresIn: '1h', // Override default expiration
            algorithm: 'HS512', // Use a different algorithm
            audience: 'your-app',
            issuer: 'your-company',
        });
    }

}